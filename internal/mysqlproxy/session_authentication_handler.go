package mysqlproxy

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/dakatsuka/masqman/internal/audit"
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
	auditor     audit.Logger
}

type clientSessionConfig struct {
	Config            appconfig.Config
	Verifier          otp.Verifier
	RemoteAddr        string
	CacheInvalidator  cacheInvalidator
	UpstreamConnector upstreamSessionConnector
	RequireTLS        bool
	AuditLogger       audit.Logger
}

type clientSession struct {
	AuthHandler server.AuthenticationHandler
	Handler     server.Handler
	deferred    *deferredSessionHandler
}

func newClientSession(config clientSessionConfig) clientSession {
	sessionHandler := newDeferredSessionHandlerWithAudit(
		config.Config.SQLPolicyConfig(),
		masking.NewPolicy(config.Config.Masking),
		resourceLimits{
			maxQueryBytes:  config.Config.RateLimits.MaxQueryBytes,
			maxResultRows:  config.Config.RateLimits.MaxResultRows,
			maxResultBytes: config.Config.RateLimits.MaxResultBytes,
		},
		config.AuditLogger,
		auditIdentity{sourceAddr: sourceAddress(config.RemoteAddr)},
	)
	connector := config.UpstreamConnector
	if connector == nil {
		connector = newUpstreamConnector(config.Config)
	}
	authHandler := newSessionAuthenticationHandlerWithAudit(
		newOTPAuthenticationHandler(config.Verifier, config.RemoteAddr, config.CacheInvalidator),
		connector,
		sessionHandler,
		config.RequireTLS,
		config.AuditLogger,
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
	return newSessionAuthenticationHandlerWithAudit(credentials, connector, session, requireTLS, nil)
}

func newSessionAuthenticationHandlerWithAudit(
	credentials *otpAuthenticationHandler,
	connector upstreamSessionConnector,
	session *deferredSessionHandler,
	requireTLS bool,
	auditor audit.Logger,
) *sessionAuthenticationHandler {
	return &sessionAuthenticationHandler{
		credentials: credentials,
		connector:   connector,
		session:     session,
		requireTLS:  requireTLS,
		auditor:     auditor,
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
	_ = handler.auditAuth("", "reject", "auth_failure")
}

func (handler *sessionAuthenticationHandler) recordAuthSuccess(username string, localAddr string) error {
	upstream, err := handler.connector.Connect(context.Background())
	if err != nil {
		return err
	}
	if err := handler.session.Activate(upstream); err != nil {
		return err
	}
	user, err := handler.credentials.consumeAuthSuccess(username, localAddr)
	if err != nil {
		_ = handler.session.Close()

		return err
	}
	identity := auditIdentity{userID: user.ID, sourceAddr: handler.credentials.sourceAddr}
	if err := handler.auditAuth(identity.userID, "allow", ""); err != nil {
		_ = handler.session.Close()

		return err
	}
	handler.session.SetAuditIdentity(identity)

	return nil
}

func (handler *sessionAuthenticationHandler) auditAuth(userID string, decision string, errorClass string) error {
	if handler.auditor == nil {
		return nil
	}

	return handler.auditor.Log(context.Background(), audit.Event{
		Time:       time.Now(),
		Kind:       audit.EventAuth,
		UserID:     userID,
		SourceAddr: handler.credentials.sourceAddr,
		Decision:   decision,
		ErrorClass: errorClass,
	})
}

func isTLSConnection(conn *server.Conn) bool {
	if conn == nil || conn.Conn == nil {
		return false
	}
	_, ok := conn.Conn.Conn.(*tls.Conn)

	return ok
}

var _ server.AuthenticationHandler = (*sessionAuthenticationHandler)(nil)
