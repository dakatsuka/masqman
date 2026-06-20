package mysqlproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

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
	protocolServer    protocolServer
	upstreamConnector upstreamSessionConnector
	listen            listenFunc
}

type serverConfig struct {
	Config            appconfig.Config
	Verifier          otp.Verifier
	ProtocolServer    protocolServer
	UpstreamConnector upstreamSessionConnector
	Listen            listenFunc
}

type listenFunc func(network string, address string) (net.Listener, error)

// NewServer builds a MySQL proxy server from validated Masqman configuration.
func NewServer(config appconfig.Config, verifier otp.Verifier) (*Server, error) {
	protocolServer, err := newGoMySQLProtocolServer(config)
	if err != nil {
		return nil, err
	}

	return newServer(serverConfig{
		Config:         config,
		Verifier:       verifier,
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
	var wg sync.WaitGroup
	defer wg.Wait()
	sessionSlots := make(chan struct{}, server.config.RateLimits.MaxMySQLSessions)

	handler := newClientConnectionHandler(clientConnectionHandlerConfig{
		Config:            server.config,
		Verifier:          server.verifier,
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

		wg.Add(1)
		go func() {
			defer func() {
				<-sessionSlots
				wg.Done()
			}()
			_ = handler.ServeConn(conn)
		}()
	}
}
