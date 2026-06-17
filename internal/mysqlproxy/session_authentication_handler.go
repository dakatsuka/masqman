package mysqlproxy

import (
	"context"

	appconfig "github.com/dakatsuka/masqman/internal/config"
	"github.com/dakatsuka/masqman/internal/otp"

	"github.com/go-mysql-org/go-mysql/server"
)

type upstreamSessionConnector interface {
	Connect(context.Context) (upstreamSession, error)
}

type sessionAuthenticationHandler struct {
	credentials *otpAuthenticationHandler
	connector   upstreamSessionConnector
	session     *deferredSessionHandler
}

type clientSessionConfig struct {
	Config            appconfig.Config
	Verifier          otp.Verifier
	RemoteAddr        string
	CacheInvalidator  cacheInvalidator
	UpstreamConnector upstreamSessionConnector
}

type clientSession struct {
	AuthHandler server.AuthenticationHandler
	Handler     server.Handler
}

func newClientSession(config clientSessionConfig) clientSession {
	sessionHandler := newDeferredSessionHandler(config.Config.SQLPolicyConfig())
	connector := config.UpstreamConnector
	if connector == nil {
		connector = newUpstreamConnector(config.Config)
	}
	authHandler := newSessionAuthenticationHandler(
		newOTPAuthenticationHandler(config.Verifier, config.RemoteAddr, config.CacheInvalidator),
		connector,
		sessionHandler,
	)

	return clientSession{
		AuthHandler: authHandler,
		Handler:     sessionHandler,
	}
}

func newSessionAuthenticationHandler(
	credentials *otpAuthenticationHandler,
	connector upstreamSessionConnector,
	session *deferredSessionHandler,
) *sessionAuthenticationHandler {
	return &sessionAuthenticationHandler{
		credentials: credentials,
		connector:   connector,
		session:     session,
	}
}

func (handler *sessionAuthenticationHandler) GetCredential(
	username string,
) (server.Credential, bool, error) {
	return handler.credentials.GetCredential(username)
}

func (handler *sessionAuthenticationHandler) OnAuthSuccess(conn *server.Conn) error {
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
		_ = upstream.Close()

		return err
	}

	return nil
}

var _ server.AuthenticationHandler = (*sessionAuthenticationHandler)(nil)
