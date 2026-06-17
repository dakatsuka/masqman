package mysqlproxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/otp"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

func TestOTPAuthenticationHandlerExposesPendingCredential(t *testing.T) {
	t.Parallel()

	verifier := &recordingVerifier{
		pending: otp.PendingCredential{
			Username:             "alice-otp",
			User:                 auth.User{ID: "alice"},
			ExpiresAt:            time.Now().Add(time.Minute),
			AuthVerifierMaterial: []byte("secret"),
		},
	}
	handler := newOTPAuthenticationHandler(verifier, "10.0.0.1:60000", nil)

	credential, found, err := handler.GetCredential("alice-otp")
	if err != nil {
		t.Fatalf("GetCredential() error = %v, want nil", err)
	}
	if !found {
		t.Fatal("GetCredential() found = false, want true")
	}
	if credential.AuthPluginName != mysql.AUTH_CACHING_SHA2_PASSWORD {
		t.Fatalf("AuthPluginName = %q, want %q", credential.AuthPluginName, mysql.AUTH_CACHING_SHA2_PASSWORD)
	}
	if len(credential.Passwords) != 1 || credential.Passwords[0] != "secret" {
		t.Fatalf("Passwords = %#v, want secret", credential.Passwords)
	}
	if verifier.pendingUsername != "alice-otp" {
		t.Fatalf("PendingCredential username = %q, want alice-otp", verifier.pendingUsername)
	}
	if verifier.pendingSourceAddr != "10.0.0.1" {
		t.Fatalf("PendingCredential sourceAddr = %q, want 10.0.0.1", verifier.pendingSourceAddr)
	}
}

func TestOTPAuthenticationHandlerHidesUnavailableCredentials(t *testing.T) {
	t.Parallel()

	verifier := &recordingVerifier{pendingErr: otp.ErrCredentialNotFound}
	handler := newOTPAuthenticationHandler(verifier, "10.0.0.1:60000", nil)

	credential, found, err := handler.GetCredential("missing-otp")
	if err != nil {
		t.Fatalf("GetCredential() error = %v, want nil", err)
	}
	if found {
		t.Fatalf("GetCredential() credential = %#v, found = true, want false", credential)
	}
}

func TestOTPAuthenticationHandlerRecordsAuthFailure(t *testing.T) {
	t.Parallel()

	verifier := &recordingVerifier{}
	handler := newOTPAuthenticationHandler(verifier, "10.0.0.1:60000", nil)
	handler.recordAuthFailure("alice-otp")

	if verifier.failureUsername != "alice-otp" {
		t.Fatalf("RecordFailure username = %q, want alice-otp", verifier.failureUsername)
	}
	if verifier.failureSourceAddr != "10.0.0.1" {
		t.Fatalf("RecordFailure sourceAddr = %q, want 10.0.0.1", verifier.failureSourceAddr)
	}
}

func TestOTPAuthenticationHandlerConsumesOnSuccessAndInvalidatesCache(t *testing.T) {
	t.Parallel()

	verifier := &recordingVerifier{}
	var invalidatedUsername string
	var invalidatedHost string
	handler := newOTPAuthenticationHandler(
		verifier,
		"10.0.0.1:60000",
		cacheInvalidatorFunc(func(username string, host string) {
			invalidatedUsername = username
			invalidatedHost = host
		}),
	)

	if err := handler.recordAuthSuccess("alice-otp", "127.0.0.1:3307"); err != nil {
		t.Fatalf("recordAuthSuccess() error = %v, want nil", err)
	}
	if verifier.consumedUsername != "alice-otp" {
		t.Fatalf("Consume username = %q, want alice-otp", verifier.consumedUsername)
	}
	if invalidatedUsername != "alice-otp" || invalidatedHost != "127.0.0.1:3307" {
		t.Fatalf("invalidated = %q %q, want alice-otp 127.0.0.1:3307", invalidatedUsername, invalidatedHost)
	}
}

func TestOTPAuthenticationHandlerRejectsConsumeFailure(t *testing.T) {
	t.Parallel()

	verifier := &recordingVerifier{consumeErr: otp.ErrCredentialLocked}
	handler := newOTPAuthenticationHandler(verifier, "10.0.0.1:60000", nil)

	err := handler.recordAuthSuccess("alice-otp", "127.0.0.1:3307")
	if !errors.Is(err, otp.ErrCredentialLocked) {
		t.Fatalf("recordAuthSuccess() error = %v, want %v", err, otp.ErrCredentialLocked)
	}
}

type recordingVerifier struct {
	pending    otp.PendingCredential
	pendingErr error
	consumeErr error
	failureErr error

	pendingUsername   string
	pendingSourceAddr string
	consumedUsername  string
	failureUsername   string
	failureSourceAddr string
}

func (verifier *recordingVerifier) PendingCredential(
	_ context.Context,
	username string,
	sourceAddr string,
) (otp.PendingCredential, error) {
	verifier.pendingUsername = username
	verifier.pendingSourceAddr = sourceAddr

	return verifier.pending, verifier.pendingErr
}

func (verifier *recordingVerifier) Consume(_ context.Context, username string) (auth.User, error) {
	verifier.consumedUsername = username

	return verifier.pending.User, verifier.consumeErr
}

func (verifier *recordingVerifier) RecordFailure(_ context.Context, username string, sourceAddr string) error {
	verifier.failureUsername = username
	verifier.failureSourceAddr = sourceAddr

	return verifier.failureErr
}

var (
	_ otp.Verifier                 = (*recordingVerifier)(nil)
	_ server.AuthenticationHandler = (*otpAuthenticationHandler)(nil)
)
