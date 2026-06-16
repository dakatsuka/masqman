package otp_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/otp"
)

func TestStoreIssuesSingleUseCredential(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := otp.NewStore(otp.StoreConfig{
		TTL:                     10 * time.Minute,
		CredentialFailureLimit:  3,
		SourceFailureLimit:      10,
		SourceFailureWindow:     10 * time.Minute,
		CredentialUsernameBytes: 12,
		CredentialPasswordBytes: 24,
		Now:                     func() time.Time { return now },
		Random:                  bytes.NewReader(bytes.Repeat([]byte{0x41}, 128)),
	})

	issued, err := store.Issue(context.Background(), auth.User{ID: "alice"}, "session-a")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if len(issued.Username) < 16 || len(issued.Password) < 32 {
		t.Fatalf("Issue returned weak-looking credential %#v", issued)
	}

	pending, err := store.PendingCredential(context.Background(), issued.Username, "127.0.0.1")
	if err != nil {
		t.Fatalf("PendingCredential returned error: %v", err)
	}
	if !bytes.Equal(pending.AuthVerifierMaterial, []byte(issued.Password)) {
		t.Fatalf("PendingCredential material = %q, want issued password", pending.AuthVerifierMaterial)
	}

	user, err := store.Consume(context.Background(), issued.Username)
	if err != nil {
		t.Fatalf("Consume returned error: %v", err)
	}
	if user.ID != "alice" {
		t.Fatalf("Consume user = %#v, want alice", user)
	}

	_, err = store.PendingCredential(context.Background(), issued.Username, "127.0.0.1")
	if !errors.Is(err, otp.ErrCredentialNotFound) {
		t.Fatalf("PendingCredential after consume error = %v, want %v", err, otp.ErrCredentialNotFound)
	}
}

func TestStoreExpiresCredentials(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := otp.NewStore(otp.StoreConfig{
		TTL:                     time.Minute,
		CredentialFailureLimit:  3,
		SourceFailureLimit:      10,
		SourceFailureWindow:     10 * time.Minute,
		CredentialUsernameBytes: 12,
		CredentialPasswordBytes: 24,
		Now:                     func() time.Time { return now },
		Random:                  bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)),
	})

	issued, err := store.Issue(context.Background(), auth.User{ID: "alice"}, "session-a")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	now = now.Add(2 * time.Minute)
	_, err = store.PendingCredential(context.Background(), issued.Username, "127.0.0.1")
	if !errors.Is(err, otp.ErrCredentialExpired) {
		t.Fatalf("PendingCredential error = %v, want %v", err, otp.ErrCredentialExpired)
	}
}

func TestStoreDoesNotConsumeExpiredCredential(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := otp.NewStore(otp.StoreConfig{
		TTL:                     time.Minute,
		CredentialFailureLimit:  3,
		SourceFailureLimit:      10,
		SourceFailureWindow:     10 * time.Minute,
		CredentialUsernameBytes: 12,
		CredentialPasswordBytes: 24,
		Now:                     func() time.Time { return now },
		Random:                  bytes.NewReader(bytes.Repeat([]byte{0x44}, 128)),
	})

	issued, err := store.Issue(context.Background(), auth.User{ID: "alice"}, "session-a")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	now = now.Add(2 * time.Minute)
	_, err = store.Consume(context.Background(), issued.Username)
	if !errors.Is(err, otp.ErrCredentialExpired) {
		t.Fatalf("Consume error = %v, want %v", err, otp.ErrCredentialExpired)
	}
}

func TestStoreRateLimitsCredentialAndSourceFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := otp.NewStore(otp.StoreConfig{
		TTL:                     10 * time.Minute,
		CredentialFailureLimit:  2,
		SourceFailureLimit:      3,
		SourceFailureWindow:     10 * time.Minute,
		CredentialUsernameBytes: 12,
		CredentialPasswordBytes: 24,
		Now:                     func() time.Time { return now },
		Random:                  bytes.NewReader(bytes.Repeat([]byte{0x43}, 256)),
	})

	issued, err := store.Issue(context.Background(), auth.User{ID: "alice"}, "session-a")
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if err := store.RecordFailure(context.Background(), issued.Username, "10.0.0.1"); err != nil {
		t.Fatalf("RecordFailure returned error: %v", err)
	}
	if err := store.RecordFailure(context.Background(), issued.Username, "10.0.0.1"); err != nil {
		t.Fatalf("RecordFailure returned error: %v", err)
	}

	_, err = store.PendingCredential(context.Background(), issued.Username, "10.0.0.2")
	if !errors.Is(err, otp.ErrCredentialLocked) {
		t.Fatalf("PendingCredential error = %v, want %v", err, otp.ErrCredentialLocked)
	}

	for i := 0; i < 3; i++ {
		if err := store.RecordFailure(context.Background(), "missing", "10.0.0.9"); err != nil {
			t.Fatalf("RecordFailure source %d returned error: %v", i, err)
		}
	}

	_, err = store.PendingCredential(context.Background(), "missing", "10.0.0.9")
	if !errors.Is(err, otp.ErrSourceRateLimited) {
		t.Fatalf("PendingCredential error = %v, want %v", err, otp.ErrSourceRateLimited)
	}
}

func TestStoreRateLimitsCredentialIssuanceByUserAndSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := otp.NewStore(otp.StoreConfig{
		TTL:                            10 * time.Minute,
		CredentialFailureLimit:         3,
		SourceFailureLimit:             10,
		SourceFailureWindow:            10 * time.Minute,
		CredentialIssuanceUserLimit:    2,
		CredentialIssuanceSessionLimit: 1,
		CredentialIssuanceWindow:       10 * time.Minute,
		CredentialUsernameBytes:        12,
		CredentialPasswordBytes:        24,
		Now:                            func() time.Time { return now },
		Random:                         bytes.NewReader(bytes.Repeat([]byte{0x45}, 512)),
	})

	if _, err := store.Issue(context.Background(), auth.User{ID: "alice"}, "session-a"); err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	_, err := store.Issue(context.Background(), auth.User{ID: "alice"}, "session-a")
	if !errors.Is(err, otp.ErrIssuanceRateLimited) {
		t.Fatalf("Issue same session error = %v, want %v", err, otp.ErrIssuanceRateLimited)
	}

	if _, err := store.Issue(context.Background(), auth.User{ID: "alice"}, "session-b"); err != nil {
		t.Fatalf("Issue second session returned error: %v", err)
	}
	_, err = store.Issue(context.Background(), auth.User{ID: "alice"}, "session-c")
	if !errors.Is(err, otp.ErrIssuanceRateLimited) {
		t.Fatalf("Issue over user limit error = %v, want %v", err, otp.ErrIssuanceRateLimited)
	}
}
