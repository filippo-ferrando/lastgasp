// Package store saves log records in SQLite or PostgreSQL.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Record is one stored log line.
type Record struct {
	ID         int64     `json:"id"`
	Host       string    `json:"host"`
	BootID     string    `json:"boot_id"`
	Source     string    `json:"source"` // kmsg or pstore
	Seq        uint64    `json:"seq"`
	Facility   int       `json:"facility"`
	Level      int       `json:"level"`
	TsUsec     uint64    `json:"ts_usec"`
	Part       int       `json:"part"`
	Parts      int       `json:"parts"`
	Message    string    `json:"message"`
	ReceivedAt time.Time `json:"received_at"`
	DedupKey   string    `json:"-"`
	ContentKey string    `json:"-"`
}

// Filter selects records. Zero values mean no filter.
type Filter struct {
	Host     string
	BootID   string
	Source   string
	MaxLevel int // 0..7, -1 for all
	Text     string
	AfterID  int64
	BeforeID int64
	Limit    int
	Oldest   bool // oldest first, also implied by AfterID
}

// HostInfo summarizes the boots seen for a host.
type HostInfo struct {
	Host      string    `json:"host"`
	Boots     int       `json:"boots"`
	LastBoot  string    `json:"last_boot"`
	FirstSeen time.Time `json:"first_seen"`
}

// Store is a database handle.
type Store struct {
	db       *sql.DB
	postgres bool
}

// Open connects to PostgreSQL when dsn starts with postgres:// or postgresql://, otherwise opens a SQLite file.
func Open(dsn string) (*Store, error) {
	s := &Store{postgres: strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")}
	var err error
	if s.postgres {
		s.db, err = sql.Open("pgx", dsn)
	} else {
		s.db, err = sql.Open("sqlite", "file:"+dsn+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
		// One connection avoids "database is locked" errors between writers.
		s.db.SetMaxOpenConns(1)
	}
	if err != nil {
		return nil, err
	}
	if err := s.migrate(context.Background()); err != nil {
		s.db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	id := "INTEGER PRIMARY KEY AUTOINCREMENT"
	if s.postgres {
		id = "BIGSERIAL PRIMARY KEY"
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS records (
			id ` + id + `,
			host TEXT NOT NULL,
			boot_id TEXT NOT NULL,
			source TEXT NOT NULL,
			seq BIGINT NOT NULL,
			facility INTEGER NOT NULL,
			level INTEGER NOT NULL,
			ts_usec BIGINT NOT NULL,
			part INTEGER NOT NULL,
			parts INTEGER NOT NULL,
			message TEXT NOT NULL,
			received_at BIGINT NOT NULL,
			dedup_key TEXT NOT NULL UNIQUE,
			content_key TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS records_host_id ON records (host, id)`,
		`CREATE INDEX IF NOT EXISTS records_content ON records (content_key)`,
		`CREATE INDEX IF NOT EXISTS records_received ON records (received_at)`,
		`CREATE TABLE IF NOT EXISTS boots (
			host TEXT NOT NULL,
			boot_id TEXT NOT NULL,
			first_seen BIGINT NOT NULL,
			PRIMARY KEY (host, boot_id))`,
		`CREATE TABLE IF NOT EXISTS pstore_files (
			host TEXT NOT NULL,
			file_id TEXT NOT NULL,
			boot_id TEXT NOT NULL,
			PRIMARY KEY (host, file_id))`,
		`CREATE TABLE IF NOT EXISTS streams (
			host TEXT NOT NULL,
			boot_id TEXT NOT NULL,
			instance TEXT NOT NULL,
			state TEXT NOT NULL,
			PRIMARY KEY (host, boot_id, instance))`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id ` + id + `,
			host TEXT NOT NULL,
			boot_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			severity INTEGER NOT NULL,
			rule TEXT NOT NULL,
			opened_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL,
			closed_at BIGINT NOT NULL,
			first_record_id BIGINT NOT NULL,
			last_record_id BIGINT NOT NULL,
			count INTEGER NOT NULL,
			summary TEXT NOT NULL,
			alert TEXT NOT NULL,
			acked_at BIGINT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS incidents_host ON incidents (host, opened_at)`,
		`CREATE INDEX IF NOT EXISTS incidents_alert ON incidents (alert, severity)`,
	}
	// Every statement above is safe to run again, so it also brings old databases without a version to version 1.
	migrations := [][]string{
		stmts,
		{
			`DROP INDEX IF EXISTS incidents_alert`,
			`ALTER TABLE incidents DROP COLUMN alert`,
			`ALTER TABLE incidents ADD COLUMN resolved INTEGER NOT NULL DEFAULT 0`,
			`CREATE TABLE alerts (
				incident_id BIGINT NOT NULL,
				target TEXT NOT NULL,
				state TEXT NOT NULL,
				updated_at BIGINT NOT NULL,
				PRIMARY KEY (incident_id, target))`,
		},
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var version int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&version); err != nil {
		return err
	}
	for v := version; v < len(migrations); v++ {
		if err := s.applyMigration(ctx, v+1, migrations[v]); err != nil {
			return fmt.Errorf("version %d: %w", v+1, err)
		}
	}
	return nil
}

// applyMigration runs one schema step in a transaction and records its version.
func (s *Store) applyMigration(ctx context.Context, version int, stmts []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM schema_version`)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO schema_version (version) VALUES (?)`), version); err != nil {
		return err
	}
	return tx.Commit()
}

// q turns "?" placeholders into "$1, $2, ..." for PostgreSQL.
func (s *Store) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// RecordBoot remembers when a boot was first seen and reports whether it was new.
// Calling it again for a known boot does nothing.
func (s *Store) RecordBoot(ctx context.Context, host, boot string, seen time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`INSERT INTO boots (host, boot_id, first_seen) VALUES (?, ?, ?)
		ON CONFLICT (host, boot_id) DO NOTHING`), host, boot, seen.UnixNano())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// PreviousBoot returns the boot seen just before boot, or "" when there is none.
func (s *Store) PreviousBoot(ctx context.Context, host, boot string) (string, error) {
	var prev string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT boot_id FROM boots WHERE host = ? AND first_seen <
		(SELECT first_seen FROM boots WHERE host = ? AND boot_id = ?) ORDER BY first_seen DESC LIMIT 1`),
		host, host, boot).Scan(&prev)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return prev, err
}

// PstoreBoot returns the boot a pstore file belongs to. The first time a file is seen, it is
// assigned to the boot seen just before currentBoot, because pstore holds the previous boot's logs.
func (s *Store) PstoreBoot(ctx context.Context, host, fileID, currentBoot string) (string, error) {
	var boot string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT boot_id FROM pstore_files WHERE host = ? AND file_id = ?`), host, fileID).Scan(&boot)
	if err == nil {
		return boot, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	if boot, err = s.PreviousBoot(ctx, host, currentBoot); err != nil {
		return "", err
	}
	if boot == "" {
		boot = "unknown"
	}
	if _, err := s.db.ExecContext(ctx, s.q(`INSERT INTO pstore_files (host, file_id, boot_id) VALUES (?, ?, ?)
		ON CONFLICT (host, file_id) DO NOTHING`), host, fileID, boot); err != nil {
		return "", err
	}
	return boot, nil
}

// InsertBatch stores records in one transaction and reports which ones were new. New records get their ID set.
// A pstore record is skipped when the same line already arrived through kmsg before the crash.
func (s *Store) InsertBatch(ctx context.Context, recs []*Record) ([]bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	insert, err := tx.PrepareContext(ctx, s.q(`INSERT INTO records
		(host, boot_id, source, seq, facility, level, ts_usec, part, parts, message, received_at, dedup_key, content_key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (dedup_key) DO NOTHING RETURNING id`))
	if err != nil {
		return nil, err
	}
	defer insert.Close()
	exists, err := tx.PrepareContext(ctx, s.q(`SELECT 1 FROM records WHERE content_key = ? AND source = 'kmsg' LIMIT 1`))
	if err != nil {
		return nil, err
	}
	defer exists.Close()

	out := make([]bool, len(recs))
	for i, r := range recs {
		if r.Source == "pstore" {
			var one int
			err := exists.QueryRowContext(ctx, r.ContentKey).Scan(&one)
			if err == nil {
				continue
			}
			if err != sql.ErrNoRows {
				return nil, err
			}
		}
		err := insert.QueryRowContext(ctx, r.Host, r.BootID, r.Source, int64(r.Seq), r.Facility, r.Level,
			int64(r.TsUsec), r.Part, r.Parts, r.Message, r.ReceivedAt.UnixMilli(), r.DedupKey, r.ContentKey).Scan(&r.ID)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[i] = true
	}
	return out, tx.Commit()
}

// Query returns records matching f, newest first unless f.Oldest or f.AfterID is set.
func (s *Store) Query(ctx context.Context, f Filter) ([]Record, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where = append(where, cond); args = append(args, v) }
	if f.Host != "" {
		add("host = ?", f.Host)
	}
	if f.BootID != "" {
		add("boot_id = ?", f.BootID)
	}
	if f.Source != "" {
		add("source = ?", f.Source)
	}
	if f.MaxLevel >= 0 && f.MaxLevel < 7 {
		add("level <= ?", f.MaxLevel)
	}
	if f.Text != "" {
		// % and _ in the search text are matched as plain characters.
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(f.Text))
		add(`LOWER(message) LIKE ? ESCAPE '\'`, "%"+esc+"%")
	}
	if f.AfterID > 0 {
		add("id > ?", f.AfterID)
	}
	if f.BeforeID > 0 {
		add("id < ?", f.BeforeID)
	}
	query := `SELECT id, host, boot_id, source, seq, facility, level, ts_usec, part, parts, message, received_at FROM records`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	if f.Oldest || f.AfterID > 0 {
		query += " ORDER BY id ASC"
	} else {
		query += " ORDER BY id DESC"
	}
	limit := f.Limit
	if limit <= 0 || limit > 10000 {
		limit = 500
	}
	query += " LIMIT " + strconv.Itoa(limit)

	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var seq, ts, recv int64
		if err := rows.Scan(&r.ID, &r.Host, &r.BootID, &r.Source, &seq, &r.Facility, &r.Level, &ts, &r.Part, &r.Parts, &r.Message, &recv); err != nil {
			return nil, err
		}
		r.Seq, r.TsUsec, r.ReceivedAt = uint64(seq), uint64(ts), time.UnixMilli(recv).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// Hosts lists every host that has sent at least one packet.
func (s *Store) Hosts(ctx context.Context) ([]HostInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host, boot_id, first_seen FROM boots ORDER BY host, first_seen`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostInfo
	for rows.Next() {
		var host, boot string
		var seen int64
		if err := rows.Scan(&host, &boot, &seen); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].Host != host {
			out = append(out, HostInfo{Host: host, FirstSeen: time.Unix(0, seen).UTC()})
		}
		h := &out[len(out)-1]
		h.Boots++
		h.LastBoot = boot
	}
	return out, rows.Err()
}

// SaveStream stores the gap tracking state of one agent instance as JSON.
func (s *Store) SaveStream(ctx context.Context, host, boot, instance, state string) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO streams (host, boot_id, instance, state) VALUES (?, ?, ?, ?)
		ON CONFLICT (host, boot_id, instance) DO UPDATE SET state = excluded.state`), host, boot, instance, state)
	return err
}

// DeleteStream removes the saved state of one agent instance.
func (s *Store) DeleteStream(ctx context.Context, host, boot, instance string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM streams WHERE host = ? AND boot_id = ? AND instance = ?`), host, boot, instance)
	return err
}

// DeleteRecordsBefore removes records received before t, in batches so the database is never locked for long.
func (s *Store) DeleteRecordsBefore(ctx context.Context, t time.Time) (int64, error) {
	var total int64
	for {
		res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM records WHERE id IN
			(SELECT id FROM records WHERE received_at < ? LIMIT 5000)`), t.UnixMilli())
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		total += n
		if err != nil || n == 0 {
			return total, err
		}
	}
}

// DeleteBootsBefore removes boots first seen before t, but keeps the newest boot of each host
// so pstore files of the next boot can still be assigned.
func (s *Store) DeleteBootsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM boots WHERE first_seen < ? AND first_seen <
		(SELECT MAX(b.first_seen) FROM boots b WHERE b.host = boots.host)`), t.UnixNano())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LoadStreams returns every saved stream state.
func (s *Store) LoadStreams(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state FROM streams`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var st string
		if err := rows.Scan(&st); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}
