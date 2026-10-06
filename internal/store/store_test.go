package store

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// openStores returns a SQLite store, plus a PostgreSQL one when LASTGASP_TEST_PG is set.
func openStores(t *testing.T) map[string]*Store {
	t.Helper()
	out := map[string]*Store{}
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	out["sqlite"] = s
	if dsn := os.Getenv("LASTGASP_TEST_PG"); dsn != "" {
		pg, err := Open(dsn)
		if err != nil {
			t.Fatal(err)
		}
		for _, tbl := range []string{"records", "boots", "pstore_files", "streams", "incidents", "alerts"} {
			pg.db.Exec("DELETE FROM " + tbl)
		}
		t.Cleanup(func() { pg.Close() })
		out["postgres"] = pg
	}
	return out
}

func rec(source, dedup, content, msg string, level int) *Record {
	return &Record{Host: "h1", BootID: "b1", Source: source, Level: level, Part: 1, Parts: 1,
		Message: msg, ReceivedAt: time.Now(), DedupKey: dedup, ContentKey: content}
}

func TestInsertDeduplicates(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			got, err := s.InsertBatch(ctx, []*Record{rec("kmsg", "k1", "c1", "a", 6), rec("kmsg", "k1", "c1", "a", 6), rec("kmsg", "k2", "c2", "b", 3)})
			if err != nil {
				t.Fatal(err)
			}
			if !got[0] || got[1] || !got[2] {
				t.Fatalf("got %v", got)
			}
			// pstore line already received through kmsg.
			got, err = s.InsertBatch(ctx, []*Record{rec("pstore", "p1", "c1", "a", 6), rec("pstore", "p2", "c9", "crash", 0)})
			if err != nil {
				t.Fatal(err)
			}
			if got[0] || !got[1] {
				t.Fatalf("pstore dedup: got %v", got)
			}
			all, _ := s.Query(ctx, Filter{MaxLevel: -1})
			if len(all) != 3 {
				t.Fatalf("stored %d records, want 3", len(all))
			}
		})
	}
}

func TestQueryFilters(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			r := rec("kmsg", "x1", "x1", "Disk FAILURE", 2)
			r.Host = "h2"
			s.InsertBatch(ctx, []*Record{rec("kmsg", "k1", "c1", "hello", 6), rec("pstore", "p1", "c2", "panic", 0), r})

			check := func(f Filter, want int) {
				t.Helper()
				got, err := s.Query(ctx, f)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != want {
					t.Fatalf("filter %+v: got %d, want %d", f, len(got), want)
				}
			}
			check(Filter{MaxLevel: -1}, 3)
			check(Filter{MaxLevel: 3}, 2)
			check(Filter{MaxLevel: -1, Host: "h2"}, 1)
			check(Filter{MaxLevel: -1, Source: "pstore"}, 1)
			check(Filter{MaxLevel: -1, Text: "failure"}, 1)
			check(Filter{MaxLevel: -1, Text: "FAILURE"}, 1)
			check(Filter{MaxLevel: -1, Limit: 2}, 2)
			check(Filter{MaxLevel: -1, Text: "%"}, 0)
			check(Filter{MaxLevel: -1, Text: "_"}, 0)

			newest, _ := s.Query(ctx, Filter{MaxLevel: -1})
			if newest[0].Message != "Disk FAILURE" {
				t.Fatal("default order should be newest first")
			}
			after, _ := s.Query(ctx, Filter{MaxLevel: -1, AfterID: newest[2].ID})
			if len(after) != 2 || after[0].ID > after[1].ID {
				t.Fatal("after_id results should be oldest first")
			}
		})
	}
}

func TestPstoreBootIsPreviousBoot(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			t0 := time.Now()
			s.RecordBoot(ctx, "h1", "boot-a", t0)
			s.RecordBoot(ctx, "h1", "boot-b", t0.Add(time.Hour))
			s.RecordBoot(ctx, "h1", "boot-b", t0.Add(2*time.Hour)) // known boot, ignored

			boot, err := s.PstoreBoot(ctx, "h1", "f1", "boot-b")
			if err != nil || boot != "boot-a" {
				t.Fatalf("got %q, %v", boot, err)
			}
			// The same file sent again from a later boot keeps its first assignment.
			s.RecordBoot(ctx, "h1", "boot-c", t0.Add(3*time.Hour))
			if boot, _ := s.PstoreBoot(ctx, "h1", "f1", "boot-c"); boot != "boot-a" {
				t.Fatalf("got %q", boot)
			}
			if boot, _ := s.PstoreBoot(ctx, "h1", "f2", "boot-a"); boot != "unknown" {
				t.Fatalf("first boot should give unknown, got %q", boot)
			}
			hosts, _ := s.Hosts(ctx)
			if len(hosts) != 1 || hosts[0].Boots != 3 || hosts[0].LastBoot != "boot-c" {
				t.Fatalf("hosts %+v", hosts)
			}
		})
	}
}

func TestStreams(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s.SaveStream(ctx, "h", "b", "1", `{"v":1}`)
			s.SaveStream(ctx, "h", "b", "1", `{"v":2}`)
			got, err := s.LoadStreams(ctx)
			if err != nil || len(got) != 1 || got[0] != `{"v":2}` {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
}

func TestPlaceholders(t *testing.T) {
	s := &Store{postgres: true}
	if got := s.q("a = ? AND b = ?"); got != "a = $1 AND b = $2" {
		t.Fatal(got)
	}
}

func TestInsertSetsIDs(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			a, b := rec("kmsg", "i1", "c1", "a", 6), rec("kmsg", "i1", "c1", "a", 6)
			if _, err := s.InsertBatch(context.Background(), []*Record{a, b}); err != nil {
				t.Fatal(err)
			}
			if a.ID == 0 || b.ID != 0 {
				t.Fatalf("ids %d %d", a.ID, b.ID)
			}
		})
	}
}

func TestRecordBootReportsNew(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			t0 := time.Now()
			if n, err := s.RecordBoot(ctx, "h1", "a", t0); err != nil || !n {
				t.Fatalf("first: %v %v", n, err)
			}
			if n, _ := s.RecordBoot(ctx, "h1", "a", t0); n {
				t.Fatal("known boot reported as new")
			}
			s.RecordBoot(ctx, "h1", "b", t0.Add(time.Second))
			if p, _ := s.PreviousBoot(ctx, "h1", "b"); p != "a" {
				t.Fatalf("previous %q", p)
			}
			if p, _ := s.PreviousBoot(ctx, "h1", "a"); p != "" {
				t.Fatalf("previous of first boot %q", p)
			}
		})
	}
}

func TestIncidents(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().Truncate(time.Millisecond)
			since := now.Add(-time.Hour)
			crit := &Incident{Host: "h1", BootID: "b", Kind: "kernel_error", Severity: SeverityCritical, Rule: "panic",
				Summary: "Kernel panic", Count: 1, OpenedAt: now, UpdatedAt: now}
			info := &Incident{Host: "h1", BootID: "b", Kind: "reboot", Severity: SeverityInfo, OpenedAt: now, UpdatedAt: now}
			pending := &Incident{Host: "h2", BootID: "b", Kind: "reboot", Severity: SeverityCritical, OpenedAt: now, UpdatedAt: now}
			old := &Incident{Host: "h3", BootID: "b", Kind: "silent", Severity: SeverityWarning, OpenedAt: now, UpdatedAt: since.Add(-time.Second)}
			for _, i := range []*Incident{crit, info, pending, old} {
				if err := s.CreateIncident(ctx, i); err != nil || i.ID == 0 {
					t.Fatalf("create: %v", err)
				}
			}
			// An open reboot waits for the crash check, info is below the minimum, old is too old.
			got, err := s.PendingAlerts(ctx, "slack", SeverityWarning, since, 10)
			if err != nil || len(got) != 1 || got[0].ID != crit.ID || got[0].Resolve || got[0].Summary != "Kernel panic" || !got[0].OpenedAt.Equal(now) {
				t.Fatalf("pending %+v %v", got, err)
			}
			pending.ClosedAt, pending.Kind = now, "crash"
			if err := s.UpdateIncident(ctx, pending); err != nil {
				t.Fatal(err)
			}
			s.SetAlert(ctx, crit.ID, "slack", AlertSent, now)
			got, _ = s.PendingAlerts(ctx, "slack", SeverityWarning, since, 10)
			if len(got) != 1 || got[0].ID != pending.ID || got[0].Kind != "crash" {
				t.Fatalf("pending after update %+v", got)
			}
			// Each target keeps its own state.
			if got, _ := s.PendingAlerts(ctx, "pager", SeverityWarning, since, 10); len(got) != 2 {
				t.Fatalf("pager pending %d", len(got))
			}
			// A resolved incident is pending again, as a resolve, only for targets that got the alert.
			crit.ClosedAt, crit.Resolved = now, true
			s.UpdateIncident(ctx, crit)
			got, _ = s.PendingAlerts(ctx, "slack", SeverityWarning, since, 10)
			if len(got) != 2 || !got[1].Resolve || got[1].ID != crit.ID {
				t.Fatalf("resolve pending %+v", got)
			}
			s.SetAlert(ctx, crit.ID, "slack", AlertResolved, now)
			if got, _ := s.PendingAlerts(ctx, "slack", SeverityWarning, since, 10); len(got) != 1 {
				t.Fatalf("after resolve %+v", got)
			}
			if err := s.AckIncident(ctx, crit.ID, now); err != nil {
				t.Fatal(err)
			}
			if err := s.AckIncident(ctx, 9999, now); err != ErrNotFound {
				t.Fatalf("ack unknown: %v", err)
			}
			one, _ := s.GetIncident(ctx, crit.ID)
			if one.AckedAt.IsZero() || !one.Resolved || len(one.Alerts) != 1 || one.Alerts[0] != (AlertState{"slack", AlertResolved}) {
				t.Fatalf("got %+v", one)
			}
			if err := s.ResetAlerts(ctx, crit.ID); err != nil {
				t.Fatal(err)
			}
			if one, _ := s.GetIncident(ctx, crit.ID); len(one.Alerts) != 0 {
				t.Fatalf("alerts not reset: %+v", one.Alerts)
			}
			if _, err := s.GetIncident(ctx, 9999); err != ErrNotFound {
				t.Fatalf("get unknown: %v", err)
			}
			open, _ := s.Incidents(ctx, IncidentFilter{OpenOnly: true})
			if len(open) != 2 {
				t.Fatalf("open %d", len(open))
			}
			if l, _ := s.Incidents(ctx, IncidentFilter{Host: "h2"}); len(l) != 1 {
				t.Fatalf("host filter %d", len(l))
			}
			// Only closed incidents are removed by retention.
			if n, err := s.DeleteIncidentsBefore(ctx, now.Add(time.Hour)); err != nil || n != 2 {
				t.Fatalf("deleted %d %v", n, err)
			}
		})
	}
}

func TestResolveKind(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now()
			a := &Incident{Host: "h", BootID: "b", Kind: "kernel_error", OpenedAt: now, UpdatedAt: now, ClosedAt: now}
			b := &Incident{Host: "h", BootID: "b", Kind: "kernel_error", OpenedAt: now, UpdatedAt: now}
			c := &Incident{Host: "h", BootID: "other", Kind: "kernel_error", OpenedAt: now, UpdatedAt: now, ClosedAt: now}
			for _, i := range []*Incident{a, b, c} {
				s.CreateIncident(ctx, i)
			}
			if err := s.ResolveKind(ctx, "h", "b", "kernel_error"); err != nil {
				t.Fatal(err)
			}
			for i, want := range map[*Incident]bool{a: true, b: false, c: false} {
				if got, _ := s.GetIncident(ctx, i.ID); got.Resolved != want {
					t.Errorf("incident %d resolved %v, want %v", i.ID, got.Resolved, want)
				}
			}
		})
	}
}

func TestMigratesVersionOneDatabase(t *testing.T) {
	dsns := map[string]string{"sqlite": filepath.Join(t.TempDir(), "old.db")}
	if dsn := os.Getenv("LASTGASP_TEST_PG"); dsn != "" {
		dsns["postgres"] = dsn
	}
	for name, dsn := range dsns {
		t.Run(name, func(t *testing.T) {
			s, err := Open(dsn)
			if err != nil {
				t.Fatal(err)
			}
			// Turn it back into a version 1 database: alert column, no alerts table, no version.
			for _, q := range []string{`DROP TABLE alerts`, `ALTER TABLE incidents DROP COLUMN resolved`,
				`ALTER TABLE incidents ADD COLUMN alert TEXT NOT NULL DEFAULT ''`, `DROP TABLE schema_version`} {
				if _, err := s.db.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			s.Close()
			if s, err = Open(dsn); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			i := &Incident{Host: "h", Kind: "crash", OpenedAt: time.Now(), UpdatedAt: time.Now()}
			if err := s.CreateIncident(context.Background(), i); err != nil {
				t.Fatal(err)
			}
			if err := s.SetAlert(context.Background(), i.ID, "t", AlertSent, time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeleteOldRecordsAndBoots(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now()
			old := rec("kmsg", "o1", "o1", "old", 6)
			old.ReceivedAt = now.Add(-48 * time.Hour)
			s.InsertBatch(ctx, []*Record{old, rec("kmsg", "n1", "n1", "new", 6)})
			if n, err := s.DeleteRecordsBefore(ctx, now.Add(-24*time.Hour)); err != nil || n != 1 {
				t.Fatalf("deleted %d %v", n, err)
			}
			all, _ := s.Query(ctx, Filter{MaxLevel: -1})
			if len(all) != 1 || all[0].Message != "new" {
				t.Fatalf("left %+v", all)
			}
			// The newest boot of a host is kept even when it is old.
			s.RecordBoot(ctx, "h1", "a", now.Add(-72*time.Hour))
			s.RecordBoot(ctx, "h1", "b", now.Add(-48*time.Hour))
			s.RecordBoot(ctx, "h2", "c", now.Add(-48*time.Hour))
			if n, err := s.DeleteBootsBefore(ctx, now.Add(-24*time.Hour)); err != nil || n != 1 {
				t.Fatalf("deleted %d boots, %v", n, err)
			}
			hosts, _ := s.Hosts(ctx)
			if len(hosts) != 2 || hosts[0].LastBoot != "b" || hosts[0].Boots != 1 {
				t.Fatalf("hosts %+v", hosts)
			}
		})
	}
}

func TestOpenRejectsURIPath(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "a?b.db")); err == nil {
		t.Fatal("path with ? accepted")
	}
}

func TestOpenIncidentsIsNotPaged(t *testing.T) {
	s := openStores(t)["sqlite"]
	ctx := context.Background()
	for i := 0; i < 1200; i++ {
		inc := &Incident{Host: "h", BootID: "b", Kind: "kernel_error", Rule: strconv.Itoa(i), OpenedAt: time.Now(), UpdatedAt: time.Now()}
		if err := s.CreateIncident(ctx, inc); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.OpenIncidents(ctx)
	if err != nil || len(l) != 1200 {
		t.Fatalf("got %d, err %v", len(l), err)
	}
}
