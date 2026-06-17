package mysqlproxy

import (
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
}

func newForwardingHandler(upstream upstreamSession) *forwardingHandler {
	return &forwardingHandler{upstream: upstream}
}

func newSessionHandler(config sqlpolicy.Config, upstream upstreamSession) server.Handler {
	return newPolicyHandler(config, newForwardingHandler(upstream))
}

func (handler *forwardingHandler) UseDB(database string) error {
	return handler.upstream.UseDB(database)
}

func (handler *forwardingHandler) HandleQuery(query string) (*mysql.Result, error) {
	result, err := handler.upstream.Execute(query)
	if err != nil {
		return nil, err
	}
	if result != nil && result.Status&mysql.SERVER_MORE_RESULTS_EXISTS != 0 {
		_ = handler.upstream.Close()

		return nil, unsupportedError()
	}

	return result, nil
}

var (
	_ server.Handler  = (*forwardingHandler)(nil)
	_ upstreamSession = (*client.Conn)(nil)
)
