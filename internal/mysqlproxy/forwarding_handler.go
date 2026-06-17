package mysqlproxy

import (
	"errors"

	"github.com/dakatsuka/masqman/internal/sqlpolicy"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

type upstreamSession interface {
	UseDB(database string) error
	Execute(query string, args ...any) (*mysql.Result, error)
	Close() error
}

type forwardingHandler struct {
	unsupportedHandler

	upstream upstreamSession
	closed   bool
	terminal error
}

func newForwardingHandler(upstream upstreamSession) *forwardingHandler {
	return &forwardingHandler{upstream: upstream}
}

func newSessionHandler(config sqlpolicy.Config, upstream upstreamSession) server.Handler {
	return newPolicyHandler(config, newForwardingHandler(upstream))
}

func (handler *forwardingHandler) UseDB(database string) error {
	if handler.closed {
		return unsupportedError()
	}

	err := handler.upstream.UseDB(database)
	if isTerminalUpstreamError(err) {
		_ = handler.closeTerminal(err)
	}

	return err
}

func (handler *forwardingHandler) HandleQuery(query string) (*mysql.Result, error) {
	if handler.closed {
		return nil, unsupportedError()
	}

	result, err := handler.upstream.Execute(query)
	if err != nil {
		if isTerminalUpstreamError(err) {
			_ = handler.closeTerminal(err)
		}

		return nil, err
	}
	if result != nil && result.Status&mysql.SERVER_MORE_RESULTS_EXISTS != 0 {
		err := unsupportedError()
		_ = handler.closeTerminal(err)

		return nil, err
	}

	return result, nil
}

func (handler *forwardingHandler) Close() error {
	if handler.closed {
		return nil
	}
	handler.closed = true

	return handler.upstream.Close()
}

func (handler *forwardingHandler) isClosed() bool {
	return handler.closed
}

func (handler *forwardingHandler) terminalError() error {
	return handler.terminal
}

func (handler *forwardingHandler) closeTerminal(err error) error {
	if handler.terminal == nil {
		handler.terminal = err
	}

	return handler.Close()
}

func isTerminalUpstreamError(err error) bool {
	if err == nil {
		return false
	}
	var mysqlErr *mysql.MyError

	return !errors.As(err, &mysqlErr)
}

var (
	_ server.Handler  = (*forwardingHandler)(nil)
	_ upstreamSession = (*client.Conn)(nil)
)
