package otp

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
)

func TestStorePrunesEmptyRateLimitBuckets(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		TTL:                            10 * time.Minute,
		CredentialFailureLimit:         3,
		SourceFailureLimit:             10,
		SourceFailureWindow:            time.Minute,
		CredentialIssuanceUserLimit:    10,
		CredentialIssuanceSessionLimit: 10,
		CredentialIssuanceWindow:       time.Minute,
		CredentialUsernameBytes:        12,
		CredentialPasswordBytes:        24,
		Now:                            func() time.Time { return now },
		Random:                         bytes.NewReader(bytes.Repeat([]byte{0x41}, 512)),
	})

	if _, err := store.PendingCredential(context.Background(), "missing", "10.0.0.1"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("PendingCredential error = %v, want %v", err, ErrCredentialNotFound)
	}
	if len(store.sources) != 0 {
		t.Fatalf("PendingCredential created empty source buckets: %#v", store.sources)
	}

	if err := store.RecordFailure(context.Background(), "missing", "10.0.0.1"); err != nil {
		t.Fatalf("RecordFailure returned error: %v", err)
	}
	if len(store.sources) != 1 {
		t.Fatalf("RecordFailure sources len = %d, want 1", len(store.sources))
	}

	now = now.Add(2 * time.Minute)
	if _, err := store.PendingCredential(context.Background(), "missing", "10.0.0.1"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("PendingCredential after window error = %v, want %v", err, ErrCredentialNotFound)
	}
	if len(store.sources) != 0 {
		t.Fatalf("expired source bucket was not pruned: %#v", store.sources)
	}

	if _, err := store.Issue(context.Background(), auth.User{ID: "alice"}, "session-a"); err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if len(store.userIssues) != 1 || len(store.sessionIssues) != 1 {
		t.Fatalf("Issue bucket lens = users %d sessions %d, want 1 and 1", len(store.userIssues), len(store.sessionIssues))
	}

	now = now.Add(2 * time.Minute)
	if _, err := store.Issue(context.Background(), auth.User{ID: "alice"}, "session-a"); err != nil {
		t.Fatalf("Issue after window returned error: %v", err)
	}
	if len(store.userIssues) != 1 || len(store.sessionIssues) != 1 {
		t.Fatalf("expired issuance buckets were not pruned before append: users %#v sessions %#v", store.userIssues, store.sessionIssues)
	}
}
