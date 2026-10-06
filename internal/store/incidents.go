package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Severity orders incidents from info to critical.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

var severityNames = []string{"info", "warning", "critical"}

func (s Severity) String() string {
	if s >= 0 && int(s) < len(severityNames) {
		return severityNames[s]
	}
	return "severity(" + strconv.Itoa(int(s)) + ")"
}

// ParseSeverity reads "info", "warning" or "critical".
func ParseSeverity(name string) (Severity, error) {
	for i, n := range severityNames {
		if n == name {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q", name)
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	*s = v
	return err
}

// Alert states, kept per incident and alert target.
const (
	AlertSent       = "sent"
	AlertSuppressed = "suppressed"
	AlertResolved   = "resolved" // a second alert said the problem is over
	AlertSkipped    = "skipped"  // the problem was over before the alert went out, so nothing was sent
	AlertFailed     = "failed"   // the target refused the alert for good, or kept failing, so it was given up
)

// AlertState is the alert state of an incident for one target.
type AlertState struct {
	Target string `json:"target"`
	State  string `json:"state"`
}

// Incident is a crash, reboot, silent host or kernel error found in the logs of one boot.
type Incident struct {
	ID       int64    `json:"id"`
	Host     string   `json:"host"`
	BootID   string   `json:"boot_id"`
	Kind     string   `json:"kind"`
	Severity Severity `json:"severity"`
	Rule     string   `json:"rule,omitempty"`
	// Records of the boot up to LastRecordID explain the incident.
	FirstRecordID int64     `json:"first_record_id"`
	LastRecordID  int64     `json:"last_record_id"`
	Count         int       `json:"count"`
	Summary       string    `json:"summary"`
	OpenedAt      time.Time `json:"opened_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	ClosedAt      time.Time `json:"closed_at,omitzero"`
	AckedAt       time.Time `json:"acked_at,omitzero"`
	// Resolved means the problem is over, so targets that got an alert get a second one.
	Resolved bool         `json:"resolved"`
	Alerts   []AlertState `json:"alerts"`
}

// Open reports whether the incident is still going on.
func (i *Incident) Open() bool { return i.ClosedAt.IsZero() }

// IncidentFilter selects incidents. Zero values mean no filter.
type IncidentFilter struct {
	Host     string
	Kind     string
	OpenOnly bool
	Limit    int
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMs(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

const incidentCols = `i.id, i.host, i.boot_id, i.kind, i.severity, i.rule, i.opened_at, i.updated_at, i.closed_at,
	i.first_record_id, i.last_record_id, i.count, i.summary, i.resolved, i.acked_at`

func scanIncident(sc interface{ Scan(...any) error }) (Incident, error) {
	var i Incident
	var opened, updated, closed, acked int64
	var resolved int
	err := sc.Scan(&i.ID, &i.Host, &i.BootID, &i.Kind, &i.Severity, &i.Rule, &opened, &updated, &closed,
		&i.FirstRecordID, &i.LastRecordID, &i.Count, &i.Summary, &resolved, &acked)
	i.OpenedAt, i.UpdatedAt, i.ClosedAt, i.AckedAt = fromMs(opened), fromMs(updated), fromMs(closed), fromMs(acked)
	i.Resolved = resolved == 1
	i.Alerts = []AlertState{}
	return i, err
}

// CreateIncident saves a new incident and sets its ID.
func (s *Store) CreateIncident(ctx context.Context, i *Incident) error {
	return s.db.QueryRowContext(ctx, s.q(`INSERT INTO incidents (host, boot_id, kind, severity, rule, opened_at, updated_at,
		closed_at, first_record_id, last_record_id, count, summary, resolved, acked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`),
		i.Host, i.BootID, i.Kind, int(i.Severity), i.Rule, ms(i.OpenedAt), ms(i.UpdatedAt), ms(i.ClosedAt),
		i.FirstRecordID, i.LastRecordID, i.Count, i.Summary, b2i(i.Resolved), ms(i.AckedAt)).Scan(&i.ID)
}

// UpdateIncident saves the fields the detector changes. Alert and ack state are left alone.
func (s *Store) UpdateIncident(ctx context.Context, i *Incident) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE incidents SET kind = ?, severity = ?, rule = ?, updated_at = ?, closed_at = ?,
		first_record_id = ?, last_record_id = ?, count = ?, summary = ?, resolved = ? WHERE id = ?`),
		i.Kind, int(i.Severity), i.Rule, ms(i.UpdatedAt), ms(i.ClosedAt), i.FirstRecordID, i.LastRecordID, i.Count, i.Summary,
		b2i(i.Resolved), i.ID)
	return err
}

// ResolveKind marks the closed incidents of one kind in a boot as resolved.
func (s *Store) ResolveKind(ctx context.Context, host, boot, kind string) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE incidents SET resolved = 1 WHERE host = ? AND boot_id = ? AND kind = ? AND closed_at <> 0`),
		host, boot, kind)
	return err
}

// ErrNotFound is returned when an incident does not exist.
var ErrNotFound = errors.New("store: not found")

// GetIncident returns one incident with its alert states.
func (s *Store) GetIncident(ctx context.Context, id int64) (Incident, error) {
	l, err := s.queryIncidents(ctx, `SELECT `+incidentCols+` FROM incidents i WHERE i.id = ?`, id)
	if err != nil {
		return Incident{}, err
	}
	if len(l) == 0 {
		return Incident{}, ErrNotFound
	}
	return l[0], nil
}

// Incidents returns incidents matching f, newest first.
func (s *Store) Incidents(ctx context.Context, f IncidentFilter) ([]Incident, error) {
	var where []string
	var args []any
	if f.Host != "" {
		where, args = append(where, "i.host = ?"), append(args, f.Host)
	}
	if f.Kind != "" {
		where, args = append(where, "i.kind = ?"), append(args, f.Kind)
	}
	if f.OpenOnly {
		where = append(where, "i.closed_at = 0")
	}
	query := `SELECT ` + incidentCols + ` FROM incidents i`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query += " ORDER BY i.id DESC LIMIT " + strconv.Itoa(limit)
	return s.queryIncidents(ctx, query, args...)
}

// OpenIncidents returns every open incident, oldest first.
func (s *Store) OpenIncidents(ctx context.Context) ([]Incident, error) {
	return s.queryIncidents(ctx, `SELECT `+incidentCols+` FROM incidents i WHERE i.closed_at = 0 ORDER BY i.id`)
}

// PendingAlert is an incident a target has not been told about, or one that is now resolved.
type PendingAlert struct {
	Incident
	Resolve bool
}

// PendingAlerts returns, oldest first, incidents updated since since that target still has to send:
// new ones at or above min, and resolved ones the target sent an alert for.
// A reboot that is still open is waiting for the crash check and is skipped.
func (s *Store) PendingAlerts(ctx context.Context, target string, min Severity, since time.Time, limit int) ([]PendingAlert, error) {
	news, err := s.queryIncidents(ctx, `SELECT `+incidentCols+` FROM incidents i WHERE i.severity >= ? AND i.updated_at >= ?
		AND NOT (i.kind = 'reboot' AND i.closed_at = 0)
		AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.incident_id = i.id AND a.target = ?)
		ORDER BY i.id LIMIT `+strconv.Itoa(limit), int(min), ms(since), target)
	if err != nil {
		return nil, err
	}
	resolved, err := s.queryIncidents(ctx, `SELECT `+incidentCols+` FROM incidents i JOIN alerts a ON a.incident_id = i.id
		WHERE a.target = ? AND a.state = 'sent' AND i.resolved = 1 AND i.updated_at >= ? ORDER BY i.id LIMIT `+strconv.Itoa(limit),
		target, ms(since))
	if err != nil {
		return nil, err
	}
	out := make([]PendingAlert, 0, len(news)+len(resolved))
	for _, i := range news {
		out = append(out, PendingAlert{Incident: i})
	}
	for _, i := range resolved {
		out = append(out, PendingAlert{Incident: i, Resolve: true})
	}
	return out, nil
}

func (s *Store) queryIncidents(ctx context.Context, query string, args ...any) ([]Incident, error) {
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, err
	}
	var out []Incident
	byID := map[int64]int{}
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		byID[i.ID] = len(out)
		out = append(out, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(out) == 0 {
		return out, err
	}
	// Alert states of all listed incidents in one query.
	ids := make([]string, 0, len(out))
	for _, i := range out {
		ids = append(ids, strconv.FormatInt(i.ID, 10))
	}
	rows, err = s.db.QueryContext(ctx, `SELECT incident_id, target, state FROM alerts WHERE incident_id IN (`+
		strings.Join(ids, ",")+`) ORDER BY target`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var a AlertState
		if err := rows.Scan(&id, &a.Target, &a.State); err != nil {
			return nil, err
		}
		inc := &out[byID[id]]
		inc.Alerts = append(inc.Alerts, a)
	}
	return out, rows.Err()
}

// SetAlert records the alert state of an incident for one target.
func (s *Store) SetAlert(ctx context.Context, id int64, target, state string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO alerts (incident_id, target, state, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (incident_id, target) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at`),
		id, target, state, ms(now))
	return err
}

// ResetAlerts forgets all alert states of an incident, so every target alerts again.
func (s *Store) ResetAlerts(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM alerts WHERE incident_id = ?`), id)
	return err
}

// AckIncident marks an incident as seen. It returns ErrNotFound for an unknown ID.
func (s *Store) AckIncident(ctx context.Context, id int64, t time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE incidents SET acked_at = ? WHERE id = ?`), ms(t), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteIncidentsBefore removes closed incidents last updated before t, and their alert states.
func (s *Store) DeleteIncidentsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM incidents WHERE closed_at <> 0 AND updated_at < ?`), ms(t))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return n, err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM alerts WHERE incident_id NOT IN (SELECT id FROM incidents)`)
	return n, err
}
