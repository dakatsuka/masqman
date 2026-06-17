package mysqlproxy

import (
	"github.com/dakatsuka/masqman/internal/sqlpolicy"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

type deferredSessionHandler struct {
	policy     server.Handler
	forwarding *deferredForwardingHandler
}

type deferredForwardingHandler struct {
	unsupportedHandler

	pendingDatabase string
	forwarding      *forwardingHandler
}

func newDeferredSessionHandler(config sqlpolicy.Config) *deferredSessionHandler {
	forwarding := &deferredForwardingHandler{}

	return &deferredSessionHandler{
		policy:     newPolicyHandler(config, forwarding),
		forwarding: forwarding,
	}
}

func (handler *deferredSessionHandler) Activate(upstream upstreamSession) error {
	return handler.forwarding.Activate(upstream)
}

func (handler *deferredSessionHandler) UseDB(database string) error {
	return handler.policy.UseDB(database)
}

func (handler *deferredSessionHandler) HandleQuery(query string) (*mysql.Result, error) {
	return handler.policy.HandleQuery(query)
}

func (handler *deferredSessionHandler) HandleFieldList(table string, fieldWildcard string) ([]*mysql.Field, error) {
	return handler.policy.HandleFieldList(table, fieldWildcard)
}

func (handler *deferredSessionHandler) HandleStmtPrepare(query string) (int, int, any, error) {
	return handler.policy.HandleStmtPrepare(query)
}

func (handler *deferredSessionHandler) HandleStmtExecute(context any, query string, args []any) (*mysql.Result, error) {
	return handler.policy.HandleStmtExecute(context, query, args)
}

func (handler *deferredSessionHandler) HandleStmtClose(context any) error {
	return handler.policy.HandleStmtClose(context)
}

func (handler *deferredSessionHandler) HandleOtherCommand(command byte, data []byte) error {
	return handler.policy.HandleOtherCommand(command, data)
}

func (handler *deferredForwardingHandler) Activate(upstream upstreamSession) error {
	forwarding := newForwardingHandler(upstream)
	if handler.pendingDatabase != "" {
		if err := forwarding.UseDB(handler.pendingDatabase); err != nil {
			_ = upstream.Close()

			return err
		}
	}
	handler.forwarding = forwarding

	return nil
}

func (handler *deferredForwardingHandler) UseDB(database string) error {
	if handler.forwarding == nil {
		handler.pendingDatabase = database

		return nil
	}

	return handler.forwarding.UseDB(database)
}

func (handler *deferredForwardingHandler) HandleQuery(query string) (*mysql.Result, error) {
	if handler.forwarding == nil {
		return nil, unsupportedError()
	}

	return handler.forwarding.HandleQuery(query)
}

var (
	_ server.Handler = (*deferredSessionHandler)(nil)
	_ server.Handler = (*deferredForwardingHandler)(nil)
)
