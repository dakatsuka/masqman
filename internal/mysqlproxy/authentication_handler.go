package mysqlproxy

import (
	"context"
	"errors"
	"net"

	"github.com/dakatsuka/masqman/internal/otp"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

type cacheInvalidator interface {
	InvalidateCache(username string, host string)
}

type cacheInvalidatorFunc func(username string, host string)

func (fn cacheInvalidatorFunc) InvalidateCache(username string, host string) {
	fn(username, host)
}

type otpAuthenticationHandler struct {
	verifier         otp.Verifier
	sourceAddr       string
	cacheInvalidator cacheInvalidator
	lastUsername     string
}

func newOTPAuthenticationHandler(
	verifier otp.Verifier,
	remoteAddr string,
	cacheInvalidator cacheInvalidator,
) *otpAuthenticationHandler {
	return &otpAuthenticationHandler{
		verifier:         verifier,
		sourceAddr:       sourceAddress(remoteAddr),
		cacheInvalidator: cacheInvalidator,
	}
}

func (handler *otpAuthenticationHandler) GetCredential(
	username string,
) (server.Credential, bool, error) {
	handler.lastUsername = username

	pending, err := handler.verifier.PendingCredential(context.Background(), username, handler.sourceAddr)
	if err != nil {
		if isUnavailableCredential(err) {
			return server.Credential{}, false, nil
		}

		return server.Credential{}, false, err
	}

	password := string(pending.AuthVerifierMaterial)
	clear(pending.AuthVerifierMaterial)

	return server.Credential{
		Passwords:      []string{password},
		AuthPluginName: mysql.AUTH_CACHING_SHA2_PASSWORD,
	}, true, nil
}

func (handler *otpAuthenticationHandler) OnAuthSuccess(conn *server.Conn) error {
	return handler.recordAuthSuccess(conn.GetUser(), conn.LocalAddr().String())
}

func (handler *otpAuthenticationHandler) OnAuthFailure(conn *server.Conn, _ error) {
	handler.recordAuthFailure(conn.GetUser())
}

func (handler *otpAuthenticationHandler) recordAuthSuccess(username string, localAddr string) error {
	if username == "" {
		username = handler.lastUsername
	}

	if _, err := handler.verifier.Consume(context.Background(), username); err != nil {
		return err
	}
	if handler.cacheInvalidator != nil {
		handler.cacheInvalidator.InvalidateCache(username, localAddr)
	}

	return nil
}

func (handler *otpAuthenticationHandler) recordAuthFailure(username string) {
	if username == "" {
		username = handler.lastUsername
	}

	_ = handler.verifier.RecordFailure(context.Background(), username, handler.sourceAddr)
}

func isUnavailableCredential(err error) bool {
	return errors.Is(err, otp.ErrCredentialNotFound) ||
		errors.Is(err, otp.ErrCredentialExpired) ||
		errors.Is(err, otp.ErrCredentialLocked) ||
		errors.Is(err, otp.ErrSourceRateLimited)
}

func sourceAddress(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}

	return host
}

var _ server.AuthenticationHandler = (*otpAuthenticationHandler)(nil)
