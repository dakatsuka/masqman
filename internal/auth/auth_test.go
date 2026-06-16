package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dakatsuka/masqman/internal/auth"
)

func TestLocalProviderAuthenticatesConfiguredUser(t *testing.T) {
	t.Parallel()

	provider := auth.NewLocalProvider([]auth.LocalUser{
		{Username: "alice", Password: "secret", DisplayName: "Alice"},
	})

	user, err := provider.Authenticate(context.Background(), "alice", "secret")
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if user.ID != "alice" || user.DisplayName != "Alice" {
		t.Fatalf("Authenticate returned user %#v", user)
	}
}

func TestLocalProviderRejectsUnknownOrWrongPassword(t *testing.T) {
	t.Parallel()

	provider := auth.NewLocalProvider([]auth.LocalUser{
		{Username: "alice", Password: "secret"},
	})

	for _, tc := range []struct {
		name     string
		username string
		password string
	}{
		{name: "unknown user", username: "bob", password: "secret"},
		{name: "wrong password", username: "alice", password: "bad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := provider.Authenticate(context.Background(), tc.username, tc.password)
			if !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Fatalf("Authenticate error = %v, want %v", err, auth.ErrInvalidCredentials)
			}
		})
	}
}
