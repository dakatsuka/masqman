package auth_test

import (
	"context"
	"errors"
	"reflect"
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

func TestLocalUserTOMLTags(t *testing.T) {
	t.Parallel()

	userType := reflect.TypeOf(auth.LocalUser{})
	for _, tc := range []struct {
		field string
		tag   string
	}{
		{field: "Username", tag: "username"},
		{field: "Password", tag: "password"},
		{field: "DisplayName", tag: "display_name"},
	} {
		field, ok := userType.FieldByName(tc.field)
		if !ok {
			t.Fatalf("LocalUser missing field %s", tc.field)
		}
		if got := field.Tag.Get("toml"); got != tc.tag {
			t.Fatalf("LocalUser.%s toml tag = %q, want %q", tc.field, got, tc.tag)
		}
	}
}
