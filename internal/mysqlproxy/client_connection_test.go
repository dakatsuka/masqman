package mysqlproxy

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/config"
	"github.com/dakatsuka/masqman/internal/otp"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

var errCommandLoopDone = errors.New("command loop done")

func TestClientConnectionHandlerBuildsSessionForRemoteClient(t *testing.T) {
	t.Parallel()

	protocolServer := &recordingProtocolServer{}
	verifier := &recordingVerifier{pendingErr: otp.ErrCredentialNotFound}
	cfg := config.Default()
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	upstream := &recordingUpstream{}
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:            cfg,
		Verifier:          verifier,
		ProtocolServer:    protocolServer,
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
	})
	conn := &recordingConn{remoteAddr: "10.0.0.1:60000"}

	err := handler.ServeConn(conn)
	if !errors.Is(err, errCommandLoopDone) {
		t.Fatalf("ServeConn() error = %v, want %v", err, errCommandLoopDone)
	}
	if protocolServer.authHandler == nil {
		t.Fatal("protocol server did not receive auth handler")
	}
	if protocolServer.commandHandler == nil {
		t.Fatal("protocol server did not receive command handler")
	}

	_, found, err := protocolServer.authHandler.GetCredential("alice-otp")
	if err != nil {
		t.Fatalf("GetCredential() error = %v, want nil", err)
	}
	if found {
		t.Fatal("GetCredential() found = true, want false from empty verifier")
	}
	if verifier.pendingSourceAddr != "10.0.0.1" {
		t.Fatalf("PendingCredential sourceAddr = %q, want 10.0.0.1", verifier.pendingSourceAddr)
	}
}

func TestClientConnectionHandlerSharesDeferredSessionWithAuthActivation(t *testing.T) {
	t.Parallel()

	protocolServer := &recordingProtocolServer{}
	verifier := &recordingVerifier{}
	cfg := config.Default()
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	upstream := &recordingUpstream{}
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:            cfg,
		Verifier:          verifier,
		ProtocolServer:    protocolServer,
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
	})

	err := handler.ServeConn(&recordingConn{remoteAddr: "10.0.0.1:60000"})
	if !errors.Is(err, errCommandLoopDone) {
		t.Fatalf("ServeConn() error = %v, want %v", err, errCommandLoopDone)
	}
	if err := protocolServer.commandHandler.UseDB("app"); err != nil {
		t.Fatalf("UseDB() error = %v, want nil", err)
	}
	authHandler, ok := protocolServer.authHandler.(*sessionAuthenticationHandler)
	if !ok {
		t.Fatalf("authHandler = %T, want *sessionAuthenticationHandler", protocolServer.authHandler)
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

func TestClientConnectionHandlerRunsCommandLoop(t *testing.T) {
	t.Parallel()

	protocolConn := &recordingProtocolConn{
		commandErrors: []error{nil, errCommandLoopDone},
	}
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:            config.Default(),
		Verifier:          &recordingVerifier{},
		ProtocolServer:    &recordingProtocolServer{protocolConn: protocolConn},
		UpstreamConnector: &recordingUpstreamConnector{},
	})

	err := handler.ServeConn(&recordingConn{remoteAddr: "10.0.0.1:60000"})
	if !errors.Is(err, errCommandLoopDone) {
		t.Fatalf("ServeConn() error = %v, want %v", err, errCommandLoopDone)
	}
	if protocolConn.commandCalls != 2 {
		t.Fatalf("HandleCommand calls = %d, want 2", protocolConn.commandCalls)
	}
}

func TestClientConnectionHandlerClosesUpstreamWhenCommandLoopEnds(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:   configWithAllowedAppSchema(),
		Verifier: &recordingVerifier{},
		ProtocolServer: &recordingProtocolServer{
			authSuccessUsername: "alice-otp",
			initialDatabase:     "app",
		},
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
	})

	err := handler.ServeConn(&recordingConn{remoteAddr: "10.0.0.1:60000"})
	if !errors.Is(err, errCommandLoopDone) {
		t.Fatalf("ServeConn() error = %v, want %v", err, errCommandLoopDone)
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after command loop ended")
	}
}

func TestClientConnectionHandlerClosesUpstreamWhenClientQuits(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	protocolConn := &recordingProtocolConn{}
	protocolConn.onCommands = []func() error{
		func() error {
			protocolConn.closed = true

			return nil
		},
		func() error {
			t.Fatal("ServeConn continued command loop after protocol connection closed")

			return errCommandLoopDone
		},
	}
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:   configWithAllowedAppSchema(),
		Verifier: &recordingVerifier{},
		ProtocolServer: &recordingProtocolServer{
			protocolConn:        protocolConn,
			authSuccessUsername: "alice-otp",
			initialDatabase:     "app",
		},
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
	})

	err := handler.ServeConn(&recordingConn{remoteAddr: "10.0.0.1:60000"})
	if err != nil {
		t.Fatalf("ServeConn() error = %v, want nil", err)
	}
	if protocolConn.commandCalls != 1 {
		t.Fatalf("HandleCommand calls = %d, want 1", protocolConn.commandCalls)
	}
	if upstream.closeCalls != 1 {
		t.Fatalf("upstream Close calls = %d, want 1", upstream.closeCalls)
	}
}

func TestClientConnectionHandlerClosesUpstreamWhenProtocolSetupFailsAfterAuth(t *testing.T) {
	t.Parallel()

	serverErr := errors.New("write ok failed")
	upstream := &recordingUpstream{}
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:   configWithAllowedAppSchema(),
		Verifier: &recordingVerifier{},
		ProtocolServer: &recordingProtocolServer{
			authSuccessUsername: "alice-otp",
			initialDatabase:     "app",
			errAfterAuth:        serverErr,
		},
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
	})
	conn := &recordingConn{remoteAddr: "10.0.0.1:60000"}

	err := handler.ServeConn(conn)
	if !errors.Is(err, serverErr) {
		t.Fatalf("ServeConn() error = %v, want %v", err, serverErr)
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after protocol setup failure")
	}
	if !conn.closed {
		t.Fatal("client connection was not closed after protocol setup failure")
	}
}

func TestClientConnectionHandlerClosesUpstreamOnceWhenAuthConsumeFails(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:   configWithAllowedAppSchema(),
		Verifier: &recordingVerifier{consumeErr: otp.ErrCredentialExpired},
		ProtocolServer: &recordingProtocolServer{
			authSuccessUsername: "alice-otp",
			initialDatabase:     "app",
		},
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
	})

	err := handler.ServeConn(&recordingConn{remoteAddr: "10.0.0.1:60000"})
	if !errors.Is(err, otp.ErrCredentialExpired) {
		t.Fatalf("ServeConn() error = %v, want %v", err, otp.ErrCredentialExpired)
	}
	if upstream.closeCalls != 1 {
		t.Fatalf("upstream close calls = %d, want 1", upstream.closeCalls)
	}
}

func TestClientConnectionHandlerTerminatesSessionAfterMultiResult(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: &mysql.Result{Status: mysql.SERVER_MORE_RESULTS_EXISTS},
	}
	protocolServer := &recordingProtocolServer{
		authSuccessUsername: "alice-otp",
		initialDatabase:     "app",
	}
	protocolConn := &recordingProtocolConn{}
	protocolConn.onCommands = []func() error{
		func() error {
			_, err := protocolServer.commandHandler.HandleQuery("select id from employees")
			assertUnsupported(t, err)

			return nil
		},
		func() error {
			t.Fatal("ServeConn continued command loop after terminal handler error")

			return errCommandLoopDone
		},
	}
	protocolServer.protocolConn = protocolConn
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:            configWithAllowedAppSchema(),
		Verifier:          &recordingVerifier{},
		ProtocolServer:    protocolServer,
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
	})

	conn := &recordingConn{remoteAddr: "10.0.0.1:60000"}

	err := handler.ServeConn(conn)
	assertUnsupported(t, err)
	if protocolConn.commandCalls != 1 {
		t.Fatalf("HandleCommand calls = %d, want 1", protocolConn.commandCalls)
	}
	if upstream.executeCalls != 1 {
		t.Fatalf("upstream Execute calls = %d, want 1", upstream.executeCalls)
	}
	if upstream.closeCalls != 1 {
		t.Fatalf("upstream Close calls = %d, want 1", upstream.closeCalls)
	}
	if !conn.closed {
		t.Fatal("client connection was not closed after terminal handler error")
	}
}

func TestClientConnectionHandlerTerminatesSessionAfterUpstreamProtocolError(t *testing.T) {
	t.Parallel()

	queryErr := errors.New("upstream packet read failed")
	upstream := &recordingUpstream{queryErr: queryErr}
	protocolServer := &recordingProtocolServer{
		authSuccessUsername: "alice-otp",
		initialDatabase:     "app",
	}
	protocolConn := &recordingProtocolConn{}
	protocolConn.onCommands = []func() error{
		func() error {
			_, err := protocolServer.commandHandler.HandleQuery("select id from employees")
			if !errors.Is(err, queryErr) {
				t.Fatalf("HandleQuery() error = %v, want %v", err, queryErr)
			}

			return nil
		},
		func() error {
			t.Fatal("ServeConn continued command loop after upstream connection error")

			return errCommandLoopDone
		},
	}
	protocolServer.protocolConn = protocolConn
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:            configWithAllowedAppSchema(),
		Verifier:          &recordingVerifier{},
		ProtocolServer:    protocolServer,
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
	})
	conn := &recordingConn{remoteAddr: "10.0.0.1:60000"}

	err := handler.ServeConn(conn)
	if !errors.Is(err, queryErr) {
		t.Fatalf("ServeConn() error = %v, want %v", err, queryErr)
	}
	if protocolConn.commandCalls != 1 {
		t.Fatalf("HandleCommand calls = %d, want 1", protocolConn.commandCalls)
	}
	if upstream.executeCalls != 1 {
		t.Fatalf("upstream Execute calls = %d, want 1", upstream.executeCalls)
	}
	if upstream.closeCalls != 1 {
		t.Fatalf("upstream Close calls = %d, want 1", upstream.closeCalls)
	}
	if !conn.closed {
		t.Fatal("client connection was not closed after upstream connection error")
	}
}

func TestClientConnectionHandlerClosesConnWhenProtocolServerFails(t *testing.T) {
	t.Parallel()

	serverErr := errors.New("handshake failed")
	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:            config.Default(),
		Verifier:          &recordingVerifier{},
		ProtocolServer:    &recordingProtocolServer{err: serverErr},
		UpstreamConnector: &recordingUpstreamConnector{},
	})
	conn := &recordingConn{remoteAddr: "10.0.0.1:60000"}

	err := handler.ServeConn(conn)
	if !errors.Is(err, serverErr) {
		t.Fatalf("ServeConn() error = %v, want %v", err, serverErr)
	}
	if !conn.closed {
		t.Fatal("client connection was not closed after protocol server failure")
	}
}

type recordingProtocolServer struct {
	authHandler    server.AuthenticationHandler
	commandHandler server.Handler
	protocolConn   protocolConnection
	newConnCalls   int
	err            error
	errAfterAuth   error

	authSuccessUsername string
	initialDatabase     string

	invalidatedUsername string
	invalidatedHost     string
}

func (server *recordingProtocolServer) NewConn(
	_ net.Conn,
	authHandler server.AuthenticationHandler,
	commandHandler server.Handler,
) (protocolConnection, error) {
	server.newConnCalls++
	server.authHandler = authHandler
	server.commandHandler = commandHandler
	if server.err != nil {
		return nil, server.err
	}
	if server.initialDatabase != "" {
		if err := commandHandler.UseDB(server.initialDatabase); err != nil {
			return nil, err
		}
	}
	if server.authSuccessUsername != "" {
		sessionAuthHandler, ok := authHandler.(*sessionAuthenticationHandler)
		if !ok {
			return nil, errors.New("auth handler is not sessionAuthenticationHandler")
		}
		if err := sessionAuthHandler.recordAuthSuccess(server.authSuccessUsername, "127.0.0.1:3307"); err != nil {
			return nil, err
		}
	}
	if server.errAfterAuth != nil {
		return nil, server.errAfterAuth
	}
	if server.protocolConn == nil {
		server.protocolConn = &recordingProtocolConn{commandErrors: []error{errCommandLoopDone}}
	}

	return server.protocolConn, nil
}

func (server *recordingProtocolServer) InvalidateCache(username string, host string) {
	server.invalidatedUsername = username
	server.invalidatedHost = host
}

type recordingConn struct {
	remoteAddr string
	closed     bool
}

func (conn *recordingConn) Read(_ []byte) (int, error) {
	return 0, errors.New("unexpected read")
}

func (conn *recordingConn) Write(_ []byte) (int, error) {
	return 0, errors.New("unexpected write")
}

func (conn *recordingConn) Close() error {
	conn.closed = true

	return nil
}

func (conn *recordingConn) LocalAddr() net.Addr {
	return stringAddr("127.0.0.1:3307")
}

func (conn *recordingConn) RemoteAddr() net.Addr {
	return stringAddr(conn.remoteAddr)
}

func (conn *recordingConn) SetDeadline(time.Time) error {
	return nil
}

func (conn *recordingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (conn *recordingConn) SetWriteDeadline(time.Time) error {
	return nil
}

type stringAddr string

func (addr stringAddr) Network() string {
	return "tcp"
}

func (addr stringAddr) String() string {
	return string(addr)
}

var _ net.Conn = (*recordingConn)(nil)

func configWithAllowedAppSchema() config.Config {
	cfg := config.Default()
	cfg.Setup.AllowSchemaSelection = []string{"app"}

	return cfg
}

type recordingProtocolConn struct {
	commandCalls  int
	commandErrors []error
	onCommands    []func() error
	closed        bool
}

func (conn *recordingProtocolConn) HandleCommand() error {
	conn.commandCalls++
	if len(conn.onCommands) > 0 {
		command := conn.onCommands[0]
		conn.onCommands = conn.onCommands[1:]

		return command()
	}
	if len(conn.commandErrors) == 0 {
		return errCommandLoopDone
	}

	err := conn.commandErrors[0]
	conn.commandErrors = conn.commandErrors[1:]

	return err
}

func (conn *recordingProtocolConn) Closed() bool {
	return conn.closed
}

func TestGoMySQLProtocolServerAdapterCreatesCustomizedConn(t *testing.T) {
	t.Parallel()

	server := &fakeCacheInvalidatingServer{}
	adapter := goMySQLProtocolServerAdapter{server: server}
	authHandler := newOTPAuthenticationHandler(&recordingVerifier{}, "10.0.0.1:60000", nil)
	commandHandler := newDeferredSessionHandler(testPolicyConfig())

	if _, err := adapter.NewConn(&recordingConn{remoteAddr: "10.0.0.1:60000"}, authHandler, commandHandler); err != nil {
		t.Fatalf("NewConn() error = %v, want nil", err)
	}
	if server.authHandler != authHandler {
		t.Fatal("NewConn() did not pass auth handler to NewCustomizedConn")
	}
	if server.commandHandler != commandHandler {
		t.Fatal("NewConn() did not pass command handler to NewCustomizedConn")
	}
}

func TestGoMySQLProtocolServerAdapterInvalidatesCache(t *testing.T) {
	t.Parallel()

	server := &fakeCacheInvalidatingServer{}
	adapter := goMySQLProtocolServerAdapter{server: server}
	adapter.InvalidateCache("alice-otp", "127.0.0.1:3307")

	if server.invalidatedUsername != "alice-otp" || server.invalidatedHost != "127.0.0.1:3307" {
		t.Fatalf(
			"invalidated = %q %q, want alice-otp 127.0.0.1:3307",
			server.invalidatedUsername,
			server.invalidatedHost,
		)
	}
}

type fakeCacheInvalidatingServer struct {
	authHandler    server.AuthenticationHandler
	commandHandler server.Handler

	invalidatedUsername string
	invalidatedHost     string
}

func (srv *fakeCacheInvalidatingServer) NewCustomizedConn(
	_ net.Conn,
	authHandler server.AuthenticationHandler,
	commandHandler server.Handler,
) (*server.Conn, error) {
	srv.authHandler = authHandler
	srv.commandHandler = commandHandler

	return &server.Conn{}, nil
}

func (srv *fakeCacheInvalidatingServer) InvalidateCache(username string, host string) {
	srv.invalidatedUsername = username
	srv.invalidatedHost = host
}

var _ upstreamSessionConnector = (*recordingUpstreamConnector)(nil)
var _ otp.Verifier = (*recordingVerifier)(nil)
var _ cacheInvalidator = (*recordingProtocolServer)(nil)
