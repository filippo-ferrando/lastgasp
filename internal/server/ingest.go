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

	ch          chan *wire.Packet
	boots       map[string]bool   // host|boot already saved
	lastBoot    time.Time         // first_seen of the newest saved boot
	pstoreBoots map[string]string // host|file -> boot
	now         func() time.Time
}

func NewIngestor(st *store.Store, tr *Tracker, keys KeyLookup, m *Metrics, log *slog.Logger) *Ingestor {
	return &Ingestor{Store: st, Tracker: tr, Keys: keys, Metrics: m, Log: log,
		ch: make(chan *wire.Packet, 65536), boots: map[string]bool{}, pstoreBoots: map[string]string{}, now: time.Now}
}

// Handle checks one datagram and queues it. It never blocks; a full queue drops the packet.
func (in *Ingestor) Handle(b []byte) {
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
		return
	}
	select {
	case in.ch <- p:
	default:
		in.Metrics.QueueDropped.Inc()
	}
}

// Listen reads datagrams from conn until it is closed.
func (in *Ingestor) Listen(conn net.PacketConn) error {
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			in.Log.Warn("udp read", "err", err)
			continue
		}
		in.Handle(buf[:n])
	}
}

// Run processes queued packets in batches and saves gap state, until ctx is done.
func (in *Ingestor) Run(ctx context.Context) {
	save := time.NewTicker(5 * time.Second)
	defer save.Stop()
	batch := make([]*wire.Packet, 0, 512)
	for {
		select {
		case <-ctx.Done():
			in.drain(batch)
			in.saveStreams(context.Background())
			return
		case <-save.C:
			in.saveStreams(ctx)
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
			in.process(ctx, batch)
		}
	}
}

func (in *Ingestor) drain(batch []*wire.Packet) {
	for {
		select {
		case p := <-in.ch:
			in.process(context.Background(), append(batch[:0], p))
		default:
			return
		}
	}
}

func (in *Ingestor) process(ctx context.Context, batch []*wire.Packet) {
	now := in.now()
	recs := make([]*store.Record, 0, len(batch))
	for _, p := range batch {
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
	}
	if len(recs) == 0 {
		return
	}
	inserted, err := in.insert(ctx, recs)
	if err != nil {
		in.Log.Error("store records, batch lost", "records", len(recs), "err", err)
		in.Metrics.LostToStore.Add(float64(len(recs)))
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
