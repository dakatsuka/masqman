package mysqlproxy

import (
	"context"
	"crypto/tls"

	appconfig "github.com/dakatsuka/masqman/internal/config"
	"github.com/dakatsuka/masqman/internal/masking"
	"github.com/dakatsuka/masqman/internal/otp"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

type upstreamSessionConnector interface {
	Connect(context.Context) (upstreamSession, error)
}

type sessionAuthenticationHandler struct {
	credentials *otpAuthenticationHandler
	connector   upstreamSessionConnector
	session     *deferredSessionHandler
	requireTLS  bool
}

type clientSessionConfig struct {
	Config            appconfig.Config
	Verifier          otp.Verifier
	RemoteAddr        string
	CacheInvalidator  cacheInvalidator
	UpstreamConnector upstreamSessionConnector
	RequireTLS        bool
}

type clientSession struct {
	AuthHandler server.AuthenticationHandler
	Handler     server.Handler
	deferred    *deferredSessionHandler
}

func newClientSession(config clientSessionConfig) clientSession {
	sessionHandler := newDeferredSessionHandlerWithLimits(
		config.Config.SQLPolicyConfig(),
		masking.NewPolicy(config.Config.Masking),
		resourceLimits{
			maxQueryBytes:  config.Config.RateLimits.MaxQueryBytes,
			maxResultRows:  config.Config.RateLimits.MaxResultRows,
			maxResultBytes: config.Config.RateLimits.MaxResultBytes,
		},
	)
	connector := config.UpstreamConnector
	if connector == nil {
		connector = newUpstreamConnector(config.Config)
	}
	authHandler := newSessionAuthenticationHandler(
		newOTPAuthenticationHandler(config.Verifier, config.RemoteAddr, config.CacheInvalidator),
		connector,
		sessionHandler,
		config.RequireTLS,
	)

	return clientSession{
		AuthHandler: authHandler,
		Handler:     sessionHandler,
		deferred:    sessionHandler,
	}
}

func (session clientSession) Close() error {
	if session.deferred == nil {
		return nil
	}

	return session.deferred.Close()
}

func (session clientSession) TerminalError() error {
	if session.deferred == nil {
		return nil
	}

	return session.deferred.TerminalError()
}

func newSessionAuthenticationHandler(
	credentials *otpAuthenticationHandler,
	connector upstreamSessionConnector,
	session *deferredSessionHandler,
	requireTLS bool,
) *sessionAuthenticationHandler {
	return &sessionAuthenticationHandler{
		credentials: credentials,
		connector:   connector,
		session:     session,
		requireTLS:  requireTLS,
	}
}

func (handler *sessionAuthenticationHandler) GetCredential(
	username string,
) (server.Credential, bool, error) {
	return handler.credentials.GetCredential(username)
}

func (handler *sessionAuthenticationHandler) OnAuthSuccess(conn *server.Conn) error {
	if handler.requireTLS && !isTLSConnection(conn) {
		return mysql.NewDefaultError(mysql.ER_INSECURE_PLAIN_TEXT)
	}

	return handler.recordAuthSuccess(conn.GetUser(), conn.LocalAddr().String())
}

func (handler *sessionAuthenticationHandler) OnAuthFailure(conn *server.Conn, err error) {
	handler.credentials.OnAuthFailure(conn, err)
}

func (handler *sessionAuthenticationHandler) recordAuthSuccess(username string, localAddr string) error {
	upstream, err := handler.connector.Connect(context.Background())
	if err != nil {
		return err
	}
	if err := handler.session.Activate(upstream); err != nil {
		return err
	}
	if err := handler.credentials.recordAuthSuccess(username, localAddr); err != nil {
		_ = handler.session.Close()

		return err
	}

	return nil
}

func isTLSConnection(conn *server.Conn) bool {
	if conn == nil || conn.Conn == nil {
		return false
	}
	_, ok := conn.Conn.Conn.(*tls.Conn)

	return ok
}

var _ server.AuthenticationHandler = (*sessionAuthenticationHandler)(nil)
