package mysqlproxy

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/dakatsuka/masqman/internal/audit"
	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/config"
	"github.com/dakatsuka/masqman/internal/otp"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/go-mysql-org/go-mysql/server"
)

func TestSessionAuthenticationHandlerRejectsNonTLSWhenTLSIsRequired(t *testing.T) {
	t.Parallel()

	connector := &recordingUpstreamConnector{}
	verifier := &recordingVerifier{}
	handler := newSessionAuthenticationHandler(
		newOTPAuthenticationHandler(verifier, "10.0.0.1:60000", nil),
		connector,
		newDeferredSessionHandler(testPolicyConfig()),
		true,
	)

	err := handler.OnAuthSuccess(&server.Conn{
		Conn: packet.NewConn(&recordingConn{remoteAddr: "10.0.0.1:60000"}),
	})
	assertMySQLErrorCode(t, err, mysql.ER_INSECURE_PLAIN_TEXT)
	if connector.connected {
		t.Fatal("upstream connector was called for non-TLS client")
	}
	if verifier.consumedUsername != "" {
		t.Fatalf("Consume username = %q, want no consume", verifier.consumedUsername)
	}
}

func TestSessionAuthenticationHandlerActivatesUpstreamBeforeConsumingOTP(t *testing.T) {
	t.Parallel()

	var events []string
	upstream := &recordingUpstream{events: &events}
	connector := &recordingUpstreamConnector{upstream: upstream, events: &events}
	verifier := &recordingVerifier{events: &events}
	session := newDeferredSessionHandler(testPolicyConfig())
	if err := session.UseDB("app"); err != nil {
		t.Fatalf("UseDB() error = %v, want nil", err)
	}
	handler := newSessionAuthenticationHandler(
		newOTPAuthenticationHandler(verifier, "10.0.0.1:60000", nil),
		connector,
		session,
		false,
	)

	if err := handler.recordAuthSuccess("alice-otp", "127.0.0.1:3307"); err != nil {
		t.Fatalf("recordAuthSuccess() error = %v, want nil", err)
	}
	if !connector.connected {
		t.Fatal("upstream connector was not called")
	}
	if upstream.database != "app" {
		t.Fatalf("upstream database = %q, want app", upstream.database)
	}
	if verifier.consumedUsername != "alice-otp" {
		t.Fatalf("Consume username = %q, want alice-otp", verifier.consumedUsername)
	}
	wantEvents := []string{"connect", "use_db:app", "consume:alice-otp"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
}

func TestSessionAuthenticationHandlerDoesNotConsumeWhenUpstreamConnectFails(t *testing.T) {
	t.Parallel()

	connectErr := errors.New("connect failed")
	connector := &recordingUpstreamConnector{err: connectErr}
	verifier := &recordingVerifier{}
	handler := newSessionAuthenticationHandler(
		newOTPAuthenticationHandler(verifier, "10.0.0.1:60000", nil),
		connector,
		newDeferredSessionHandler(testPolicyConfig()),
		false,
	)

	err := handler.recordAuthSuccess("alice-otp", "127.0.0.1:3307")
	if !errors.Is(err, connectErr) {
		t.Fatalf("recordAuthSuccess() error = %v, want %v", err, connectErr)
	}
	if verifier.consumedUsername != "" {
		t.Fatalf("Consume username = %q, want no consume", verifier.consumedUsername)
	}
}

func TestSessionAuthenticationHandlerClosesUpstreamAndDoesNotConsumeWhenActivationFails(t *testing.T) {
	t.Parallel()

	activationErr := errors.New("init db failed")
	upstream := &recordingUpstream{initDBErr: activationErr}
	connector := &recordingUpstreamConnector{upstream: upstream}
	verifier := &recordingVerifier{}
	session := newDeferredSessionHandler(testPolicyConfig())
	if err := session.UseDB("app"); err != nil {
		t.Fatalf("UseDB() error = %v, want nil", err)
	}
	handler := newSessionAuthenticationHandler(
		newOTPAuthenticationHandler(verifier, "10.0.0.1:60000", nil),
		connector,
		session,
		false,
	)

	err := handler.recordAuthSuccess("alice-otp", "127.0.0.1:3307")
	if !errors.Is(err, activationErr) {
		t.Fatalf("recordAuthSuccess() error = %v, want %v", err, activationErr)
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after activation failure")
	}
	if verifier.consumedUsername != "" {
		t.Fatalf("Consume username = %q, want no consume", verifier.consumedUsername)
	}
}

func TestSessionAuthenticationHandlerClosesUpstreamWhenConsumeFails(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	connector := &recordingUpstreamConnector{upstream: upstream}
	verifier := &recordingVerifier{consumeErr: otp.ErrCredentialExpired}
	handler := newSessionAuthenticationHandler(
		newOTPAuthenticationHandler(verifier, "10.0.0.1:60000", nil),
		connector,
		newDeferredSessionHandler(testPolicyConfig()),
		false,
	)

	err := handler.recordAuthSuccess("alice-otp", "127.0.0.1:3307")
	if !errors.Is(err, otp.ErrCredentialExpired) {
		t.Fatalf("recordAuthSuccess() error = %v, want %v", err, otp.ErrCredentialExpired)
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after consume failure")
	}
}

func TestNewClientSessionComposesAuthAndDeferredHandler(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	connector := &recordingUpstreamConnector{upstream: upstream}
	verifier := &recordingVerifier{}
	cfg := config.Default()
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	clientSession := newClientSession(clientSessionConfig{
		Config:            cfg,
		Verifier:          verifier,
		RemoteAddr:        "10.0.0.1:60000",
		UpstreamConnector: connector,
	})

	if err := clientSession.Handler.UseDB("app"); err != nil {
		t.Fatalf("UseDB() error = %v, want nil", err)
	}
	authHandler, ok := clientSession.AuthHandler.(*sessionAuthenticationHandler)
	if !ok {
		t.Fatalf("AuthHandler = %T, want *sessionAuthenticationHandler", clientSession.AuthHandler)
	}
	if err := authHandler.recordAuthSuccess("alice-otp", "127.0.0.1:3307"); err != nil {
		t.Fatalf("recordAuthSuccess() error = %v, want nil", err)
	}
	if upstream.database != "app" {
		t.Fatalf("upstream database = %q, want app", upstream.database)
	}
	if verifier.consumedUsername != "alice-otp" {
		t.Fatalf("Consume username = %q, want alice-otp", verifier.consumedUsername)
	}
}

func TestNewClientSessionEnforcesConfiguredMaxQueryBytes(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	connector := &recordingUpstreamConnector{upstream: upstream}
	cfg := config.Default()
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	cfg.RateLimits.MaxQueryBytes = len("select 1")
	clientSession := newClientSession(clientSessionConfig{
		Config:            cfg,
		Verifier:          &recordingVerifier{},
		RemoteAddr:        "10.0.0.1:60000",
		UpstreamConnector: connector,
	})
	authHandler, ok := clientSession.AuthHandler.(*sessionAuthenticationHandler)
	if !ok {
		t.Fatalf("AuthHandler = %T, want *sessionAuthenticationHandler", clientSession.AuthHandler)
	}
	if err := authHandler.recordAuthSuccess("alice-otp", "127.0.0.1:3307"); err != nil {
		t.Fatalf("recordAuthSuccess() error = %v, want nil", err)
	}

	_, err := clientSession.Handler.HandleQuery("select 12")
	assertMySQLErrorCode(t, err, mysql.ER_NET_PACKET_TOO_LARGE)
	if upstream.executeCalls != 0 {
		t.Fatalf("upstream Execute calls = %d, want 0", upstream.executeCalls)
	}
}

func TestNewClientSessionEnforcesConfiguredMaxResultRows(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("id"), Type: mysql.MYSQL_TYPE_LONG}},
			[][]*string{{stringPtr("1")}, {stringPtr("2")}},
		),
	}
	connector := &recordingUpstreamConnector{upstream: upstream}
	cfg := config.Default()
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	cfg.RateLimits.MaxResultRows = 1
	clientSession := newClientSession(clientSessionConfig{
		Config:            cfg,
		Verifier:          &recordingVerifier{},
		RemoteAddr:        "10.0.0.1:60000",
		UpstreamConnector: connector,
	})
	authHandler, ok := clientSession.AuthHandler.(*sessionAuthenticationHandler)
	if !ok {
		t.Fatalf("AuthHandler = %T, want *sessionAuthenticationHandler", clientSession.AuthHandler)
	}
	if err := authHandler.recordAuthSuccess("alice-otp", "127.0.0.1:3307"); err != nil {
		t.Fatalf("recordAuthSuccess() error = %v, want nil", err)
	}

	_, err := clientSession.Handler.HandleQuery("select id from employees")
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after configured result row limit breach")
	}
}

func TestNewClientSessionEnforcesConfiguredMaxResultBytes(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("email"), Type: mysql.MYSQL_TYPE_VAR_STRING}},
			[][]*string{{stringPtr("alice@example.test")}},
		),
	}
	connector := &recordingUpstreamConnector{upstream: upstream}
	cfg := config.Default()
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	cfg.RateLimits.MaxResultBytes = int64(len(upstream.result.RowDatas[0]) - 1)
	clientSession := newClientSession(clientSessionConfig{
		Config:            cfg,
		Verifier:          &recordingVerifier{},
		RemoteAddr:        "10.0.0.1:60000",
		UpstreamConnector: connector,
	})
	authHandler, ok := clientSession.AuthHandler.(*sessionAuthenticationHandler)
	if !ok {
		t.Fatalf("AuthHandler = %T, want *sessionAuthenticationHandler", clientSession.AuthHandler)
	}
	if err := authHandler.recordAuthSuccess("alice-otp", "127.0.0.1:3307"); err != nil {
		t.Fatalf("recordAuthSuccess() error = %v, want nil", err)
	}

	_, err := clientSession.Handler.HandleQuery("select email from employees")
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after configured result byte limit breach")
	}
}

func TestNewClientSessionAuditsAuthAndQueryWithConsumedUser(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: resultWithTextRows(
			[]*mysql.Field{{Name: []byte("1"), Type: mysql.MYSQL_TYPE_LONG}},
			[][]*string{{stringPtr("1")}},
		),
	}
	logger := &recordingAuditLogger{}
	connector := &recordingUpstreamConnector{upstream: upstream}
	cfg := config.Default()
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	clientSession := newClientSession(clientSessionConfig{
		Config: cfg,
		Verifier: &recordingVerifier{
			pending: otp.PendingCredential{User: auth.User{ID: "alice", DisplayName: "Alice"}},
		},
		RemoteAddr:        "10.0.0.1:60000",
		UpstreamConnector: connector,
		AuditLogger:       logger,
	})
	authHandler, ok := clientSession.AuthHandler.(*sessionAuthenticationHandler)
	if !ok {
		t.Fatalf("AuthHandler = %T, want *sessionAuthenticationHandler", clientSession.AuthHandler)
	}
	if err := authHandler.recordAuthSuccess("alice-otp", "127.0.0.1:3307"); err != nil {
		t.Fatalf("recordAuthSuccess() error = %v, want nil", err)
	}
	if _, err := clientSession.Handler.HandleQuery("select 1"); err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}

	if len(logger.events) != 2 {
		t.Fatalf("audit event count = %d, want 2: %#v", len(logger.events), logger.events)
	}
	authEvent := logger.events[0]
	if authEvent.Kind != audit.EventAuth ||
		authEvent.UserID != "alice" ||
		authEvent.SourceAddr != "10.0.0.1" ||
		authEvent.Decision != "allow" ||
		authEvent.ErrorClass != "" {
		t.Fatalf("auth audit event = %#v", authEvent)
	}
	queryEvent := logger.events[1]
	if queryEvent.Kind != audit.EventQuery ||
		queryEvent.UserID != "alice" ||
		queryEvent.SourceAddr != "10.0.0.1" ||
		queryEvent.Decision != "allow_operational_read" {
		t.Fatalf("query audit event = %#v", queryEvent)
	}
}

func TestNewClientSessionMarksTerminalWhenQueryAuditFails(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{result: &mysql.Result{}}
	connector := &recordingUpstreamConnector{upstream: upstream}
	cfg := config.Default()
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	clientSession := newClientSession(clientSessionConfig{
		Config: cfg,
		Verifier: &recordingVerifier{
			pending: otp.PendingCredential{User: auth.User{ID: "alice"}},
		},
		RemoteAddr:        "10.0.0.1:60000",
		UpstreamConnector: connector,
		AuditLogger:       &recordingAuditLogger{err: errors.New("audit sink unavailable")},
	})
	authHandler, ok := clientSession.AuthHandler.(*sessionAuthenticationHandler)
	if !ok {
		t.Fatalf("AuthHandler = %T, want *sessionAuthenticationHandler", clientSession.AuthHandler)
	}
	if err := authHandler.recordAuthSuccess("alice-otp", "127.0.0.1:3307"); err == nil {
		t.Fatal("recordAuthSuccess() error = nil, want auth audit failure")
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after auth audit failure")
	}

	upstream = &recordingUpstream{result: &mysql.Result{}}
	clientSession = newClientSession(clientSessionConfig{
		Config: cfg,
		Verifier: &recordingVerifier{
			pending: otp.PendingCredential{User: auth.User{ID: "alice"}},
		},
		RemoteAddr:        "10.0.0.1:60000",
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
		AuditLogger: &recordingAuditLogger{
			errOnCall: 2,
			err:       errors.New("query audit sink unavailable"),
		},
	})
	authHandler, ok = clientSession.AuthHandler.(*sessionAuthenticationHandler)
	if !ok {
		t.Fatalf("AuthHandler = %T, want *sessionAuthenticationHandler", clientSession.AuthHandler)
	}
	if err := authHandler.recordAuthSuccess("alice-otp", "127.0.0.1:3307"); err != nil {
		t.Fatalf("recordAuthSuccess() error = %v, want nil", err)
	}
	_, err := clientSession.Handler.HandleQuery("select id from employees")
	assertUnsupported(t, err)
	if clientSession.TerminalError() == nil {
		t.Fatal("TerminalError() = nil after query audit failure")
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after query audit failure")
	}
}

type recordingUpstreamConnector struct {
	upstream  upstreamSession
	err       error
	connected bool
	events    *[]string
}

func (connector *recordingUpstreamConnector) Connect(context.Context) (upstreamSession, error) {
	connector.connected = true
	if connector.events != nil {
		*connector.events = append(*connector.events, "connect")
	}
	if connector.err != nil {
		return nil, connector.err
	}
	if connector.upstream == nil {
		connector.upstream = &recordingUpstream{}
	}

	return connector.upstream, nil
}
