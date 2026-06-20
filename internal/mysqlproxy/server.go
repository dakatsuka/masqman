package mysqlproxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/dakatsuka/masqman/internal/audit"
	appconfig "github.com/dakatsuka/masqman/internal/config"
	"github.com/dakatsuka/masqman/internal/otp"

	"github.com/go-mysql-org/go-mysql/mysql"
	gomysqlserver "github.com/go-mysql-org/go-mysql/server"
)

// Server accepts client MySQL connections and serves each connection with
// Masqman's per-client authentication, policy, and forwarding state.
type Server struct {
	config            appconfig.Config
	verifier          otp.Verifier
	auditor           audit.Logger
	protocolServer    protocolServer
	upstreamConnector upstreamSessionConnector
	listen            listenFunc
}

type serverConfig struct {
	Config            appconfig.Config
	Verifier          otp.Verifier
	AuditLogger       audit.Logger
	ProtocolServer    protocolServer
	UpstreamConnector upstreamSessionConnector
	Listen            listenFunc
}

type listenFunc func(network string, address string) (net.Listener, error)

// NewServer builds a MySQL proxy server from validated Masqman configuration.
func NewServer(config appconfig.Config, verifier otp.Verifier, auditors ...audit.Logger) (*Server, error) {
	protocolServer, err := newGoMySQLProtocolServer(config)
	if err != nil {
		return nil, err
	}
	var auditor audit.Logger
	if len(auditors) > 0 {
		auditor = auditors[0]
	}

	return newServer(serverConfig{
		Config:         config,
		Verifier:       verifier,
		AuditLogger:    auditor,
		ProtocolServer: protocolServer,
	}), nil
}

func newGoMySQLProtocolServer(config appconfig.Config) (protocolServer, error) {
	tlsConfig, tlsEnabled, err := mysqlServerTLSConfig(config.MySQL.TLS)
	if err != nil {
		return nil, err
	}
	var rsaKey *rsa.PrivateKey
	if !tlsEnabled {
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate MySQL auth RSA key: %w", err)
		}
	}

	server := gomysqlserver.NewServer(
		"8.0.11",
		mysql.DEFAULT_COLLATION_ID,
		mysql.AUTH_CACHING_SHA2_PASSWORD,
		rsaKey,
		tlsConfig,
	)

	return goMySQLProtocolServerAdapter{server: server}, nil
}

func mysqlServerTLSConfig(config appconfig.TLS) (*tls.Config, bool, error) {
	if !config.Enabled {
		return nil, false, nil
	}

	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, false, fmt.Errorf("load MySQL TLS certificate: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, true, nil
}

func newServer(config serverConfig) *Server {
	listen := config.Listen
	if listen == nil {
		listen = net.Listen
	}

	return &Server{
		config:            config.Config,
		verifier:          config.Verifier,
		auditor:           config.AuditLogger,
		protocolServer:    config.ProtocolServer,
		upstreamConnector: config.UpstreamConnector,
		listen:            listen,
	}
}

// ListenAndServe listens on the configured MySQL address and serves client
// connections until the listener is closed or an accept error occurs.
func (server *Server) ListenAndServe() error {
	listener, err := server.listen("tcp", server.config.MySQL.ListenAddr)
	if err != nil {
		return err
	}

	return server.Serve(listener)
}

// Serve accepts client connections from listener until the listener is closed
// or Accept returns a non-close error. In-flight connection handlers are allowed
// to finish before Serve returns.
func (server *Server) Serve(listener net.Listener) error {
	return server.ServeContext(context.Background(), listener)
}

// ServeContext accepts client connections from listener until the listener is
// closed, Accept returns a non-close error, or context cancellation closes the
// listener and active client connections.
func (server *Server) ServeContext(ctx context.Context, listener net.Listener) error {
	var wg sync.WaitGroup
	sessionSlots := make(chan struct{}, server.config.RateLimits.MaxMySQLSessions)
	active := make(map[net.Conn]struct{})
	var activeMu sync.Mutex
	done := make(chan struct{})
	defer close(done)
	defer wg.Wait()
	go func() {
		select {
		case <-ctx.Done():
			activeMu.Lock()
			_ = listener.Close()
			for conn := range active {
				_ = conn.Close()
			}
			activeMu.Unlock()
		case <-done:
		}
	}()

	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:            server.config,
		Verifier:          server.verifier,
		AuditLogger:       server.auditor,
		ProtocolServer:    server.protocolServer,
		UpstreamConnector: server.upstreamConnector,
	})
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			return err
		}

		select {
		case sessionSlots <- struct{}{}:
		default:
			_ = conn.Close()

			continue
		}

		activeMu.Lock()
		if ctx.Err() != nil {
			activeMu.Unlock()
			<-sessionSlots
			_ = conn.Close()

			continue
		}
		active[conn] = struct{}{}
		activeMu.Unlock()
		wg.Add(1)
		go func(conn net.Conn) {
			defer func() {
				activeMu.Lock()
				delete(active, conn)
				activeMu.Unlock()
				<-sessionSlots
				wg.Done()
			}()
			_ = handler.ServeConn(conn)
		}(conn)
	}
}
