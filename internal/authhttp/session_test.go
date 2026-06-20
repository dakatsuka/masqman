package authhttp_test

import (
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/authhttp"
)

func TestSessionStoreCreatesAndValidatesSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := authhttp.NewSessionStore(authhttp.SessionConfig{
		IdleLifetime:     30 * time.Minute,
		AbsoluteLifetime: 12 * time.Hour,
		TokenBytes:       16,
		Now:              func() time.Time { return now },
	})

	session, err := store.Create(auth.User{ID: "alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	got, ok := store.Get(session.ID)
	if !ok {
		t.Fatal("Get did not find created session")
	}
	if got.User.ID != "alice" || got.CSRFToken == "" {
		t.Fatalf("Get returned %#v", got)
	}

	if !store.ValidateCSRF(session.ID, session.CSRFToken) {
		t.Fatal("ValidateCSRF rejected current token")
	}
	if store.ValidateCSRF(session.ID, "bad") {
		t.Fatal("ValidateCSRF accepted bad token")
	}
}

func TestSessionStoreExpiresIdleAndAbsoluteLifetimes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := authhttp.NewSessionStore(authhttp.SessionConfig{
		IdleLifetime:     time.Minute,
		AbsoluteLifetime: 2 * time.Minute,
		TokenBytes:       16,
		Now:              func() time.Time { return now },
	})

	session, err := store.Create(auth.User{ID: "alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	now = now.Add(90 * time.Second)
	if _, ok := store.Get(session.ID); ok {
		t.Fatal("Get found idle-expired session")
	}

	session, err = store.Create(auth.User{ID: "alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	now = now.Add(3 * time.Minute)
	if _, ok := store.Get(session.ID); ok {
		t.Fatal("Get found absolute-expired session")
	}
}

func TestValidateCSRFDoesNotRefreshIdleLifetime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := authhttp.NewSessionStore(authhttp.SessionConfig{
		IdleLifetime:     time.Minute,
		AbsoluteLifetime: 12 * time.Hour,
		TokenBytes:       16,
		Now:              func() time.Time { return now },
	})

	session, err := store.Create(auth.User{ID: "alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	now = now.Add(30 * time.Second)
	if !store.ValidateCSRF(session.ID, session.CSRFToken) {
		t.Fatal("ValidateCSRF rejected current token")
	}

	now = now.Add(31 * time.Second)
	if _, ok := store.Get(session.ID); ok {
		t.Fatal("Get found idle-expired session after CSRF validation")
	}
}

func TestSessionStoreDeletesSession(t *testing.T) {
	t.Parallel()

	store := authhttp.NewSessionStore(authhttp.SessionConfig{TokenBytes: 16})
	session, err := store.Create(auth.User{ID: "alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	store.Delete(session.ID)

	if _, ok := store.Get(session.ID); ok {
		t.Fatal("Get found deleted session")
	}
	if store.ValidateCSRF(session.ID, session.CSRFToken) {
		t.Fatal("ValidateCSRF accepted deleted session")
	}
}
