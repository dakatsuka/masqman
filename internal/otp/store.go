// Package otp issues and verifies short-lived one-time MySQL credentials.
package otp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
)

var (
	// ErrCredentialNotFound reports a missing or already-consumed credential.
	ErrCredentialNotFound = errors.New("credential not found")
	// ErrCredentialExpired reports a credential that has passed its expiry.
	ErrCredentialExpired = errors.New("credential expired")
	// ErrCredentialLocked reports a credential locked by failed attempts.
	ErrCredentialLocked = errors.New("credential locked")
	// ErrSourceRateLimited reports a source address blocked by failed attempts.
	ErrSourceRateLimited = errors.New("source rate limited")
	// ErrIssuanceRateLimited reports a browser credential issuance throttle.
	ErrIssuanceRateLimited = errors.New("credential issuance rate limited")
)

// Issuer creates one-time MySQL credentials for authenticated browser users.
type Issuer interface {
	Issue(ctx context.Context, user auth.User, sessionID string) (Credential, error)
}

// Verifier exposes pending verifier material and consumes credentials after a
// successful MySQL authentication exchange.
type Verifier interface {
	PendingCredential(ctx context.Context, username string, sourceAddr string) (PendingCredential, error)
	Consume(ctx context.Context, username string) (auth.User, error)
	RecordFailure(ctx context.Context, username string, sourceAddr string) error
}

// Credential is the one-time username and password displayed to an
// authenticated browser user.
type Credential struct {
	Username  string
	Password  string
	ExpiresAt time.Time
}

// PendingCredential is verifier material for the MySQL authentication plugin.
type PendingCredential struct {
	Username             string
	User                 auth.User
	ExpiresAt            time.Time
	AuthVerifierMaterial []byte
}

// StoreConfig controls in-memory credential TTLs, entropy, and failure limits.
type StoreConfig struct {
	TTL                            time.Duration
	CredentialFailureLimit         int
	SourceFailureLimit             int
	SourceFailureWindow            time.Duration
	CredentialIssuanceUserLimit    int
	CredentialIssuanceSessionLimit int
	CredentialIssuanceWindow       time.Duration
	CredentialUsernameBytes        int
	CredentialPasswordBytes        int
	Now                            func() time.Time
	Random                         io.Reader
}

// Store keeps short-lived one-time credentials and authentication failure
// counters in memory.
type Store struct {
	mu            sync.Mutex
	now           func() time.Time
	random        io.Reader
	config        StoreConfig
	credentials   map[string]*storedCredential
	sources       map[string][]time.Time
	userIssues    map[string][]time.Time
	sessionIssues map[string][]time.Time
}

type storedCredential struct {
	user      auth.User
	password  []byte
	expiresAt time.Time
	failures  int
	locked    bool
}

// NewStore creates an in-memory OTP store.
func NewStore(config StoreConfig) *Store {
	if config.TTL <= 0 {
		config.TTL = 10 * time.Minute
	}
	if config.CredentialFailureLimit <= 0 {
		config.CredentialFailureLimit = 5
	}
	if config.SourceFailureLimit <= 0 {
		config.SourceFailureLimit = 20
	}
	if config.SourceFailureWindow <= 0 {
		config.SourceFailureWindow = 10 * time.Minute
	}
	if config.CredentialIssuanceUserLimit <= 0 {
		config.CredentialIssuanceUserLimit = 10
	}
	if config.CredentialIssuanceSessionLimit <= 0 {
		config.CredentialIssuanceSessionLimit = 5
	}
	if config.CredentialIssuanceWindow <= 0 {
		config.CredentialIssuanceWindow = 10 * time.Minute
	}
	if config.CredentialUsernameBytes <= 0 {
		config.CredentialUsernameBytes = 12
	}
	if config.CredentialPasswordBytes <= 0 {
		config.CredentialPasswordBytes = 24
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}

	return &Store{
		now:           config.Now,
		random:        config.Random,
		config:        config,
		credentials:   make(map[string]*storedCredential),
		sources:       make(map[string][]time.Time),
		userIssues:    make(map[string][]time.Time),
		sessionIssues: make(map[string][]time.Time),
	}
}

// Issue creates a new credential for a browser-authenticated user.
func (s *Store) Issue(_ context.Context, user auth.User, sessionID string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.issuanceLimitedLocked(s.userIssues, user.ID, s.config.CredentialIssuanceUserLimit, now) ||
		s.issuanceLimitedLocked(s.sessionIssues, sessionID, s.config.CredentialIssuanceSessionLimit, now) {
		return Credential{}, ErrIssuanceRateLimited
	}

	username, err := randomToken(s.random, s.config.CredentialUsernameBytes)
	if err != nil {
		return Credential{}, err
	}
	password, err := randomToken(s.random, s.config.CredentialPasswordBytes)
	if err != nil {
		return Credential{}, err
	}

	expiresAt := now.Add(s.config.TTL)
	s.credentials[username] = &storedCredential{
		user:      user,
		password:  []byte(password),
		expiresAt: expiresAt,
	}
	s.userIssues[user.ID] = append(s.recentIssuanceLocked(s.userIssues, user.ID, now), now)
	s.sessionIssues[sessionID] = append(s.recentIssuanceLocked(s.sessionIssues, sessionID, now), now)

	return Credential{Username: username, Password: password, ExpiresAt: expiresAt}, nil
}

// PendingCredential returns verifier material for an unexpired, unlocked
// credential and enforces source-address throttling before exposing material.
func (s *Store) PendingCredential(
	_ context.Context,
	username string,
	sourceAddr string,
) (PendingCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.sourceLimitedLocked(sourceAddr, now) {
		return PendingCredential{}, ErrSourceRateLimited
	}

	credential, ok := s.credentials[username]
	if !ok {
		return PendingCredential{}, ErrCredentialNotFound
	}
	if now.After(credential.expiresAt) || now.Equal(credential.expiresAt) {
		clearBytes(credential.password)
		delete(s.credentials, username)
		return PendingCredential{}, ErrCredentialExpired
	}
	if credential.locked {
		return PendingCredential{}, ErrCredentialLocked
	}

	material := make([]byte, len(credential.password))
	copy(material, credential.password)

	return PendingCredential{
		Username:             username,
		User:                 credential.user,
		ExpiresAt:            credential.expiresAt,
		AuthVerifierMaterial: material,
	}, nil
}

// Consume marks a credential as used and clears retained verifier material.
func (s *Store) Consume(_ context.Context, username string) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	credential, ok := s.credentials[username]
	if !ok {
		return auth.User{}, ErrCredentialNotFound
	}
	if now := s.now(); now.After(credential.expiresAt) || now.Equal(credential.expiresAt) {
		clearBytes(credential.password)
		delete(s.credentials, username)
		return auth.User{}, ErrCredentialExpired
	}
	if credential.locked {
		return auth.User{}, ErrCredentialLocked
	}

	clearBytes(credential.password)
	delete(s.credentials, username)

	return credential.user, nil
}

// RecordFailure records a failed MySQL authentication attempt without consuming
// the credential.
func (s *Store) RecordFailure(_ context.Context, username string, sourceAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.sources[sourceAddr] = append(s.recentSourceFailuresLocked(sourceAddr, now), now)

	if credential, ok := s.credentials[username]; ok {
		credential.failures++
		if credential.failures >= s.config.CredentialFailureLimit {
			credential.locked = true
			clearBytes(credential.password)
		}
	}

	return nil
}

func (s *Store) sourceLimitedLocked(sourceAddr string, now time.Time) bool {
	return len(s.recentSourceFailuresLocked(sourceAddr, now)) >= s.config.SourceFailureLimit
}

func (s *Store) recentSourceFailuresLocked(sourceAddr string, now time.Time) []time.Time {
	windowStart := now.Add(-s.config.SourceFailureWindow)
	failures := s.sources[sourceAddr]
	kept := failures[:0]
	for _, failure := range failures {
		if failure.After(windowStart) || failure.Equal(windowStart) {
			kept = append(kept, failure)
		}
	}
	s.sources[sourceAddr] = kept

	return kept
}

func (s *Store) issuanceLimitedLocked(
	buckets map[string][]time.Time,
	key string,
	limit int,
	now time.Time,
) bool {
	return len(s.recentIssuanceLocked(buckets, key, now)) >= limit
}

func (s *Store) recentIssuanceLocked(
	buckets map[string][]time.Time,
	key string,
	now time.Time,
) []time.Time {
	windowStart := now.Add(-s.config.CredentialIssuanceWindow)
	issues := buckets[key]
	kept := issues[:0]
	for _, issuedAt := range issues {
		if issuedAt.After(windowStart) || issuedAt.Equal(windowStart) {
			kept = append(kept, issuedAt)
		}
	}
	buckets[key] = kept

	return kept
}

func randomToken(random io.Reader, size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := io.ReadFull(random, bytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func clearBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}
