package mysqlproxy

import (
	"fmt"
	"net"

	appconfig "github.com/dakatsuka/masqman/internal/config"
	"github.com/dakatsuka/masqman/internal/otp"

	"github.com/go-mysql-org/go-mysql/server"
)

type protocolServer interface {
	NewConn(net.Conn, server.AuthenticationHandler, server.Handler) (protocolConnection, error)
	cacheInvalidator
}

type protocolConnection interface {
	HandleCommand() error
	Closed() bool
}

type goMySQLServer interface {
	NewCustomizedConn(net.Conn, server.AuthenticationHandler, server.Handler) (*server.Conn, error)
	InvalidateCache(username string, host string)
}

type goMySQLProtocolServerAdapter struct {
	server goMySQLServer
}

func (adapter goMySQLProtocolServerAdapter) NewConn(
	conn net.Conn,
	authHandler server.AuthenticationHandler,
	commandHandler server.Handler,
) (protocolConnection, error) {
	serverConn, err := adapter.server.NewCustomizedConn(conn, authHandler, commandHandler)
	if err != nil {
		return nil, err
	}

	return serverConn, nil
}

func (adapter goMySQLProtocolServerAdapter) InvalidateCache(username string, host string) {
	adapter.server.InvalidateCache(username, host)
}

type clientConnectionHandlerConfig struct {
	Config            appconfig.Config
	Verifier          otp.Verifier
	ProtocolServer    protocolServer
	UpstreamConnector upstreamSessionConnector
}

type clientConnectionHandler struct {
	config            appconfig.Config
	verifier          otp.Verifier
	protocolServer    protocolServer
	upstreamConnector upstreamSessionConnector
}

func newClientConnectionHandler(config clientConnectionHandlerConfig) *clientConnectionHandler {
	return &clientConnectionHandler{
		config:            config.Config,
		verifier:          config.Verifier,
		protocolServer:    config.ProtocolServer,
		upstreamConnector: config.UpstreamConnector,
	}
}

func (handler *clientConnectionHandler) ServeConn(conn net.Conn) error {
	if handler.protocolServer == nil {
		_ = conn.Close()

		return fmt.Errorf("%w: MySQL protocol server is required", appconfig.ErrInvalid)
	}

	session := newClientSession(clientSessionConfig{
		Config:            handler.config,
		Verifier:          handler.verifier,
		RemoteAddr:        conn.RemoteAddr().String(),
		CacheInvalidator:  handler.protocolServer,
		UpstreamConnector: handler.upstreamConnector,
	})
	protocolConn, err := handler.protocolServer.NewConn(conn, session.AuthHandler, session.Handler)
	if err != nil {
		_ = session.Close()
		_ = conn.Close()

		return err
	}

	for {
		if err := protocolConn.HandleCommand(); err != nil {
			_ = session.Close()
			_ = conn.Close()

			return err
		}
		if err := session.TerminalError(); err != nil {
			_ = session.Close()
			_ = conn.Close()

			return err
		}
		if protocolConn.Closed() {
			_ = session.Close()

			return nil
		}
	}
}
