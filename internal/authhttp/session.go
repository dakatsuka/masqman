// Package authhttp contains browser authentication session support.
package authhttp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"sync"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
)

// SessionConfig controls browser session lifetimes and token entropy.
type SessionConfig struct {
	IdleLifetime     time.Duration
	AbsoluteLifetime time.Duration
	TokenBytes       int
	Now              func() time.Time
	Random           io.Reader
}

// Session is one authenticated browser session.
type Session struct {
	ID         string
	User       auth.User
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// SessionStore keeps browser sessions in memory for M1 local development.
type SessionStore struct {
	mu       sync.Mutex
	config   SessionConfig
	sessions map[string]Session
}

// NewSessionStore creates an in-memory browser session store.
func NewSessionStore(config SessionConfig) *SessionStore {
	if config.IdleLifetime <= 0 {
		config.IdleLifetime = 30 * time.Minute
	}
	if config.AbsoluteLifetime <= 0 {
		config.AbsoluteLifetime = 12 * time.Hour
	}
	if config.TokenBytes <= 0 {
		config.TokenBytes = 32
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}

	return &SessionStore{config: config, sessions: make(map[string]Session)}
}

// Create starts a browser session for an authenticated user.
func (s *SessionStore) Create(user auth.User) (Session, error) {
	id, err := randomToken(s.config.Random, s.config.TokenBytes)
	if err != nil {
		return Session{}, err
	}
	csrfToken, err := randomToken(s.config.Random, s.config.TokenBytes)
	if err != nil {
		return Session{}, err
	}

	now := s.config.Now()
	session := Session{
		ID:         id,
		User:       user,
		CSRFToken:  csrfToken,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(s.config.AbsoluteLifetime),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session

	return session, nil
}

// Get returns a live session and refreshes its idle timestamp.
func (s *SessionStore) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.getLocked(id, true)
}

// Delete removes a browser session.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, id)
}

// ValidateCSRF reports whether token matches the current session CSRF token.
func (s *SessionStore) ValidateCSRF(sessionID string, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.getLocked(sessionID, false)
	if !ok {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(token)) == 1
}

func (s *SessionStore) getLocked(id string, refreshIdle bool) (Session, bool) {
	session, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	now := s.config.Now()
	if now.Sub(session.LastSeenAt) >= s.config.IdleLifetime || !now.Before(session.ExpiresAt) {
		delete(s.sessions, id)
		return Session{}, false
	}

	if !refreshIdle {
		return session, true
	}

	session.LastSeenAt = now
	s.sessions[id] = session

	return session, true
}

func randomToken(random io.Reader, size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := io.ReadFull(random, bytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
