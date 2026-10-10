package store

import (
	"context"
	"time"
)

// EnrollToken lets agents enroll and get their own key. Only a hash of the token is kept.
type EnrollToken struct {
	ID        int64     `json:"id"`
	Comment   string    `json:"comment"`
	UsesLeft  int       `json:"uses_left"` // -1 for no limit
	Used      int       `json:"used"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// Usable reports whether the token still lets agents enroll at t.
func (e *EnrollToken) Usable(t time.Time) bool {
	return !e.Revoked && e.UsesLeft != 0 && t.Before(e.ExpiresAt)
}

// AgentKey is the key of an enrolled agent.
type AgentKey struct {
	Host       string    `json:"host"`
	Key        string    `json:"-"` // hex
	TokenID    int64     `json:"token_id"`
	From       string    `json:"from"` // address the enrollment came from
	EnrolledAt time.Time `json:"enrolled_at"`
}

// CreateEnrollToken saves a token by its hash and sets its ID.
func (s *Store) CreateEnrollToken(ctx context.Context, t *EnrollToken, hash string) error {
	return s.db.QueryRowContext(ctx, s.q(`INSERT INTO enroll_tokens (token_hash, comment, uses_left, used, expires_at, revoked,
		created_by, created_at) VALUES (?, ?, ?, 0, ?, 0, ?, ?) RETURNING id`),
		hash, t.Comment, t.UsesLeft, ms(t.ExpiresAt), t.CreatedBy, ms(t.CreatedAt)).Scan(&t.ID)
}

// EnrollTokens lists tokens, newest first.
func (s *Store) EnrollTokens(ctx context.Context) ([]EnrollToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, comment, uses_left, used, expires_at, revoked, created_by, created_at
		FROM enroll_tokens ORDER BY id DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnrollToken{}
	for rows.Next() {
		var t EnrollToken
		var expires, created int64
		var revoked int
		if err := rows.Scan(&t.ID, &t.Comment, &t.UsesLeft, &t.Used, &expires, &revoked, &t.CreatedBy, &created); err != nil {
			return nil, err
		}
		t.ExpiresAt, t.CreatedAt, t.Revoked = fromMs(expires), fromMs(created), revoked == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

// UsableToken is the ID and hex hash of a token that still lets agents enroll.
type UsableToken struct {
	ID   int64
	Hash string
}

// UsableEnrollTokens returns the tokens that are not expired, revoked or used up at now.
func (s *Store) UsableEnrollTokens(ctx context.Context, now time.Time) ([]UsableToken, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, token_hash FROM enroll_tokens
		WHERE revoked = 0 AND uses_left <> 0 AND expires_at > ? ORDER BY id LIMIT 1000`), ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UsableToken
	for rows.Next() {
		var t UsableToken
		if err := rows.Scan(&t.ID, &t.Hash); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UseEnrollToken counts one use of a token, or returns ErrNotFound when it expired, was revoked
// or is used up, also by a use in between.
func (s *Store) UseEnrollToken(ctx context.Context, id int64, now time.Time) error {
	return s.updateOne(ctx, `UPDATE enroll_tokens SET used = used + 1,
		uses_left = CASE WHEN uses_left > 0 THEN uses_left - 1 ELSE uses_left END
		WHERE id = ? AND revoked = 0 AND uses_left <> 0 AND expires_at > ?`, id, ms(now))
}

// RevokeEnrollToken stops a token. Agents that enrolled with it keep their keys.
func (s *Store) RevokeEnrollToken(ctx context.Context, id int64) error {
	return s.updateOne(ctx, `UPDATE enroll_tokens SET revoked = 1 WHERE id = ?`, id)
}

// SaveAgentKey stores the key of an enrolled agent. It fails when the host has a key already.
func (s *Store) SaveAgentKey(ctx context.Context, k *AgentKey) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO agent_keys (host, key_hex, token_id, from_addr, enrolled_at) VALUES (?, ?, ?, ?, ?)`),
		k.Host, k.Key, k.TokenID, k.From, ms(k.EnrolledAt))
	return err
}

// AgentKeys returns every enrolled agent with its key, by host.
func (s *Store) AgentKeys(ctx context.Context) ([]AgentKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host, key_hex, token_id, from_addr, enrolled_at FROM agent_keys ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentKey{}
	for rows.Next() {
		var k AgentKey
		var at int64
		if err := rows.Scan(&k.Host, &k.Key, &k.TokenID, &k.From, &at); err != nil {
			return nil, err
		}
		k.EnrolledAt = fromMs(at)
		out = append(out, k)
	}
	return out, rows.Err()
}

// DeleteAgentKey removes the key of an enrolled host, so its packets are refused. It returns ErrNotFound for an unknown host.
func (s *Store) DeleteAgentKey(ctx context.Context, host string) error {
	return s.updateOne(ctx, `DELETE FROM agent_keys WHERE host = ?`, host)
}
