package server

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"lastgasp/internal/incident"
	"lastgasp/internal/store"
	"lastgasp/internal/wire"
)

// Ingestor turns packets into stored records.
type Ingestor struct {
	Store   *store.Store
	Tracker *Tracker
	Keys    KeyLookup
	Metrics *Metrics
	Log     *slog.Logger
	// Detector is told about packets, new boots and stored records. It may be nil.
	Detector *incident.Detector
	// Enroller answers enrollment packets. Without it they count as malformed.
	Enroller *Enroller

	ch          chan inbound
	boots       map[string]bool   // host|boot already saved
	lastBoot    time.Time         // first_seen of the newest saved boot
	pstoreBoots map[string]string // host|file -> boot
	now         func() time.Time

	ackMu   sync.Mutex
	lastAck map[ackKey]time.Time // per agent run, limits acks to one per ackEvery
	// reply sends acks of version 3 heartbeats, which go out after their batch is stored.
	reply atomic.Pointer[func(b []byte, to net.Addr)]
	// listening and running tell Ready that the UDP reader and the worker are up.
	listening, running atomic.Bool
}

// inbound is a checked packet and the address it came from.
type inbound struct {
	p    *wire.Packet
	from net.Addr
}

type ackKey struct {
	host     string
	bootID   [16]byte
	instance uint64
}

// ackEvery limits acks per agent run, so replayed heartbeats cannot turn the server into a reflector.
const ackEvery = 200 * time.Millisecond

// cacheLimit bounds the in-memory caches. They are cleared when full, the database stays the source of truth.
const cacheLimit = 100000

func NewIngestor(st *store.Store, tr *Tracker, keys KeyLookup, m *Metrics, log *slog.Logger) *Ingestor {
	return &Ingestor{Store: st, Tracker: tr, Keys: keys, Metrics: m, Log: log,
		ch: make(chan inbound, 65536), boots: map[string]bool{}, pstoreBoots: map[string]string{}, now: time.Now,
		lastAck: map[ackKey]time.Time{}}
}

// Handle checks one datagram and queues it. It never blocks; a full queue drops the packet.
// It returns the ack to send back at once, or nil. A version 3 heartbeat is answered after its
// batch is stored, so the ack can tell what arrived.
func (in *Ingestor) Handle(b []byte, from net.Addr) []byte {
	if in.Enroller != nil && wire.IsEnroll(b) {
		in.Enroller.Submit(b, from)
		return nil
	}
	p, err := wire.Decode(b, in.Keys.Lookup)
	if err != nil {
		reason := "malformed"
		switch {
		case errors.Is(err, wire.ErrAuth):
			reason = "auth_failed"
		case errors.Is(err, wire.ErrUnknownHost):
			reason = "unknown_host"
		case errors.Is(err, wire.ErrVersion):
			reason = "version"
		case errors.Is(err, wire.ErrHost):
			reason = "bad_host"
		}
		in.Metrics.Invalid.WithLabelValues(reason).Inc()
		return nil
	}
	// Seq 0 is a probe: the agent asks if a server is there, before it sends its records.
	if p.Kind != wire.KindHeartbeat || p.Seq != 0 {
		select {
		case in.ch <- inbound{p, from}:
		default:
			in.Metrics.QueueDropped.Inc()
			return nil
		}
	}
	if p.Kind != wire.KindHeartbeat {
		return nil
	}
	if p.Seq == 0 {
		in.Metrics.Probes.Inc()
	} else if p.Version >= 3 {
		return nil
	}
	// A probe ack tells nothing about records: the probe is not tracked.
	return in.ack(p, 0, nil)
}

// ack builds the answer to the heartbeat p, or nil when the limit per agent run is reached.
func (in *Ingestor) ack(p *wire.Packet, upto uint64, missing []wire.Range) []byte {
	if !in.ackAllowed(ackKey{p.Host, p.BootID, p.Instance}) {
		return nil
	}
	key := in.Keys.Lookup(p.Host)
	if key == nil {
		return nil
	}
	ack, err := wire.EncodeAck(p, upto, missing, key)
	if err != nil {
		return nil
	}
	return ack
}

func (in *Ingestor) ackAllowed(k ackKey) bool {
	in.ackMu.Lock()
	defer in.ackMu.Unlock()
	now := in.now()
	if now.Sub(in.lastAck[k]) < ackEvery {
		return false
	}
	if len(in.lastAck) >= cacheLimit {
		clear(in.lastAck)
	}
	in.lastAck[k] = now
	return true
}

// Listen reads datagrams from conn until it is closed.
func (in *Ingestor) Listen(conn net.PacketConn) error {
	reply := func(b []byte, to net.Addr) { conn.WriteTo(b, to) }
	in.SetReply(reply)
	in.listening.Store(true)
	defer in.listening.Store(false)
	buf := make([]byte, 65536)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			in.Log.Warn("udp read", "err", err)
			continue
		}
		if ack := in.Handle(buf[:n], addr); ack != nil {
			// A lost ack is fine: the agent sends the next heartbeat soon.
			conn.WriteTo(ack, addr)
		}
	}
}

// Ready reports why the ingestor cannot take packets right now, or nil.
func (in *Ingestor) Ready() error {
	switch {
	case !in.listening.Load():
		return errors.New("not reading UDP packets")
	case !in.running.Load():
		return errors.New("ingest worker stopped")
	case len(in.ch) > cap(in.ch)*9/10:
		return fmt.Errorf("ingest queue %d%% full", len(in.ch)*100/cap(in.ch))
	}
	return nil
}

// SetReply sets where acks sent after storing go. Listen sets it to its socket.
func (in *Ingestor) SetReply(fn func(b []byte, to net.Addr)) { in.reply.Store(&fn) }

// Run processes queued packets in batches and saves gap state, until ctx is done.
func (in *Ingestor) Run(ctx context.Context) {
	in.running.Store(true)
	defer in.running.Store(false)
	save := time.NewTicker(5 * time.Second)
	defer save.Stop()
	batch := make([]inbound, 0, 512)
	// Packets already marked as received must reach the database, so writes are not cut by shutdown.
	work := context.WithoutCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			in.drain(work, batch)
			in.saveStreams(work)
			return
		case <-save.C:
			in.saveStreams(work)
		case p := <-in.ch:
			batch = append(batch[:0], p)
		fill:
			for len(batch) < cap(batch) {
				select {
				case p := <-in.ch:
					batch = append(batch, p)
				default:
					break fill
				}
			}
			in.process(work, batch)
		}
	}
}

// drain stores the packets still queued, in full batches.
func (in *Ingestor) drain(ctx context.Context, batch []inbound) {
	for {
		batch = batch[:0]
	fill:
		for len(batch) < cap(batch) {
			select {
			case p := <-in.ch:
				batch = append(batch, p)
			default:
				break fill
			}
		}
		if len(batch) == 0 {
			return
		}
		in.process(ctx, batch)
	}
}

func (in *Ingestor) process(ctx context.Context, batch []inbound) {
	now := in.now()
	recs := make([]*store.Record, 0, len(batch))
	pkts := make([]*wire.Packet, 0, len(batch))
	// The newest version 3 heartbeat of each agent run, answered once the batch is stored.
	beats := map[ackKey]inbound{}
	defer func() { in.sendAcks(beats) }()
	for _, b := range batch {
		p := b.p
		if !in.Tracker.Observe(p, now) {
			continue
		}
		boot := wire.FormatBootID(p.BootID)
		if err := in.ensureBoot(ctx, p.Host, boot, now); err != nil {
			in.Log.Error("save boot", "err", err)
			in.Metrics.StoreErrors.Inc()
		}
		if in.Detector != nil {
			in.Detector.Seen(p.Host, boot, now)
		}
		if p.Kind == wire.KindHeartbeat {
			if k := (ackKey{p.Host, p.BootID, p.Instance}); p.Version >= 3 && p.Seq > beats[k].seq() {
				beats[k] = b
			}
			continue
		}
		r := &p.Record
		rec := &store.Record{Host: p.Host, BootID: boot, Seq: r.Seq, Facility: int(r.Priority >> 3), Level: int(r.Priority & 7),
			TsUsec: r.TsUsec, Part: int(r.Part), Parts: int(r.Parts), Message: cleanText(r.Msg), ReceivedAt: now}
		switch p.Kind {
		case wire.KindKmsg:
			rec.Source = "kmsg"
			rec.DedupKey = "k|" + p.Host + "|" + boot + "|" + strconv.FormatUint(r.Seq, 10) + "|" + strconv.Itoa(int(r.Part))
		case wire.KindPstore:
			rec.Source = "pstore"
			fileID := strconv.FormatUint(r.FileID, 16)
			b, err := in.pstoreBoot(ctx, p.Host, fileID, boot)
			if err != nil {
				in.Log.Error("pstore boot", "err", err)
				in.Metrics.StoreErrors.Inc()
				b = "unknown"
			}
			rec.BootID = b
			rec.DedupKey = "p|" + p.Host + "|" + fileID + "|" + strconv.FormatUint(r.Seq, 10) + "|" + strconv.Itoa(int(r.Part))
		}
		rec.ContentKey = contentKey(rec)
		recs = append(recs, rec)
		pkts = append(pkts, p)
	}
	if len(recs) == 0 {
		return
	}
	inserted, err := in.insert(ctx, recs)
	if err != nil {
		// The packets count as missing again, so agents that still hold them send them again.
		in.Log.Error("store records, batch lost", "records", len(recs), "err", err)
		in.Metrics.LostToStore.Add(float64(len(recs)))
		for _, p := range pkts {
			in.Tracker.Unreceive(p)
		}
		return
	}
	if in.Detector != nil {
		in.Detector.Records(ctx, recs, inserted, now)
	}
	for i, r := range recs {
		if inserted[i] {
			in.Metrics.Stored.WithLabelValues(r.Host, r.Source).Inc()
		} else {
			in.Metrics.Deduplicated.WithLabelValues(r.Host, r.Source).Inc()
		}
	}
}

func (b inbound) seq() uint64 {
	if b.p == nil {
		return 0
	}
	return b.p.Seq
}

// sendAcks answers heartbeats with what their agent run has delivered so far.
func (in *Ingestor) sendAcks(beats map[ackKey]inbound) {
	reply := in.reply.Load()
	if reply == nil {
		return
	}
	for k, b := range beats {
		upto, missing := in.Tracker.Progress(StreamKey{k.host, wire.FormatBootID(k.bootID), k.instance})
		if ack := in.ack(b.p, upto, missing); ack != nil {
			(*reply)(ack, b.from)
		}
	}
}

// insert retries a few times, so a short database outage does not lose records.
func (in *Ingestor) insert(ctx context.Context, recs []*store.Record) ([]bool, error) {
	var err error
	for attempt, wait := 0, 100*time.Millisecond; attempt < 5; attempt, wait = attempt+1, wait*2 {
		var out []bool
		if out, err = in.Store.InsertBatch(ctx, recs); err == nil {
			return out, nil
		}
		in.Metrics.StoreErrors.Inc()
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(wait):
		}
	}
	return nil, err
}

func (in *Ingestor) ensureBoot(ctx context.Context, host, boot string, now time.Time) error {
	k := host + "|" + boot
	if in.boots[k] {
		return nil
	}
	if len(in.boots) >= cacheLimit {
		clear(in.boots)
	}
	// Boots in the same batch share now, so each gets a later time to keep their order.
	if !now.After(in.lastBoot) {
		now = in.lastBoot.Add(time.Microsecond)
	}
	isNew, err := in.Store.RecordBoot(ctx, host, boot, now)
	if err != nil {
		return err
	}
	in.boots[k] = true
	in.lastBoot = now
	if isNew && in.Detector != nil {
		prev, err := in.Store.PreviousBoot(ctx, host, boot)
		if err != nil {
			return err
		}
		in.Detector.NewBoot(ctx, host, boot, prev, now)
	}
	return nil
}

func (in *Ingestor) pstoreBoot(ctx context.Context, host, fileID, boot string) (string, error) {
	k := host + "|" + fileID
	if b, ok := in.pstoreBoots[k]; ok {
		return b, nil
	}
	b, err := in.Store.PstoreBoot(ctx, host, fileID, boot)
	if err != nil {
		return "", err
	}
	if len(in.pstoreBoots) >= cacheLimit {
		clear(in.pstoreBoots)
	}
	in.pstoreBoots[k] = b
	return b, nil
}

// contentKey matches a pstore line with the kmsg record it was copied from.
func contentKey(r *store.Record) string {
	h := sha256.New()
	for _, s := range []string{r.Host, r.BootID, r.Message} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], r.TsUsec)
	binary.BigEndian.PutUint64(b[8:], uint64(r.Part))
	h.Write(b[:])
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func (in *Ingestor) saveStreams(ctx context.Context) {
	streams := in.Tracker.TakeDirty()
	for i, s := range streams {
		state, _ := json.Marshal(s)
		if err := in.Store.SaveStream(ctx, s.Host, s.BootID, s.Instance, string(state)); err != nil {
			in.Log.Error("save stream state", "err", err)
			in.Metrics.StoreErrors.Inc()
			in.Tracker.MarkDirty(streams[i:])
			return
		}
	}
}

// LoadStreams restores gap state saved by a previous server run.
func LoadStreams(ctx context.Context, st *store.Store, tr *Tracker) error {
	states, err := st.LoadStreams(ctx)
	if err != nil {
		return err
	}
	streams := make([]Stream, 0, len(states))
	for _, s := range states {
		var v Stream
		if json.Unmarshal([]byte(s), &v) == nil {
			streams = append(streams, v)
		}
	}
	tr.Load(streams)
	return nil
}

// KeyLookup returns the key of a host, or nil when the host is not allowed.
type KeyLookup interface{ Lookup(host string) []byte }

// cleanText escapes zero bytes and invalid UTF-8 as \xNN, like the kernel does in /dev/kmsg.
// PostgreSQL refuses both, and one bad line would fail the whole batch.
func cleanText(s string) string {
	if utf8.ValidString(s) && !strings.ContainsRune(s, 0) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == 0 || (r == utf8.RuneError && n == 1) {
			fmt.Fprintf(&b, "\\x%02x", s[i])
		} else {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}
