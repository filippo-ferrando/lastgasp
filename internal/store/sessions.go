package store

import (
	"context"
	"database/sql"
	"time"
)

// CreateSession saves a login that ends at expires. Expired sessions are removed at the same time.
func (s *Store) CreateSession(ctx context.Context, hash, user string, expires, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM sessions WHERE expires_at < ?`), now.UnixMilli()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO sessions (token_hash, user_name, created_at, expires_at) VALUES (?, ?, ?, ?)`),
		hash, user, now.UnixMilli(), expires.UnixMilli())
	return err
}

// SessionUser returns the user of a session that has not expired, or ErrNotFound.
func (s *Store) SessionUser(ctx context.Context, hash string, now time.Time) (string, error) {
	var user string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT user_name FROM sessions WHERE token_hash = ? AND expires_at > ?`),
		hash, now.UnixMilli()).Scan(&user)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return user, err
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM sessions WHERE token_hash = ?`), hash)
	return err
}
