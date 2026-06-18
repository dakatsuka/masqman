package mysqlproxy

import (
	"github.com/dakatsuka/masqman/internal/masking"
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
	masker          masking.Policy
	decision        sqlpolicy.Decision
	forwarding      *forwardingHandler
	closed          bool
	terminal        error
}

func newDeferredSessionHandler(config sqlpolicy.Config) *deferredSessionHandler {
	return newDeferredSessionHandlerWithMasking(config, nil)
}

func newDeferredSessionHandlerWithMasking(
	config sqlpolicy.Config,
	masker masking.Policy,
) *deferredSessionHandler {
	return newDeferredSessionHandlerWithLimits(config, masker, resourceLimits{})
}

func newDeferredSessionHandlerWithLimits(
	config sqlpolicy.Config,
	masker masking.Policy,
	limits resourceLimits,
) *deferredSessionHandler {
	forwarding := &deferredForwardingHandler{}
	forwarding.masker = masker

	return &deferredSessionHandler{
		policy:     newPolicyHandlerWithLimits(config, limits, forwarding),
		forwarding: forwarding,
	}
}

func (handler *deferredSessionHandler) Activate(upstream upstreamSession) error {
	return handler.forwarding.Activate(upstream)
}

func (handler *deferredSessionHandler) Close() error {
	return handler.forwarding.Close()
}

func (handler *deferredSessionHandler) TerminalError() error {
	return handler.forwarding.TerminalError()
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
	if handler.closed {
		_ = upstream.Close()

		return unsupportedError()
	}

	forwarding := newForwardingHandlerWithMasking(upstream, handler.masker)
	forwarding.setQueryDecision(handler.decision)
	if handler.pendingDatabase != "" {
		if err := forwarding.UseDB(handler.pendingDatabase); err != nil {
			_ = forwarding.Close()

			return err
		}
	}
	handler.forwarding = forwarding

	return nil
}

func (handler *deferredForwardingHandler) Close() error {
	if handler.forwarding == nil {
		return nil
	}
	forwarding := handler.forwarding
	handler.deactivate(nil)

	return forwarding.Close()
}

func (handler *deferredForwardingHandler) UseDB(database string) error {
	if handler.forwarding == nil {
		if handler.closed {
			return unsupportedError()
		}
		handler.pendingDatabase = database

		return nil
	}

	err := handler.forwarding.UseDB(database)
	if handler.forwarding.isClosed() {
		handler.deactivate(handler.forwarding.terminalError())
	}

	return err
}

func (handler *deferredForwardingHandler) HandleQuery(query string) (*mysql.Result, error) {
	if handler.forwarding == nil {
		return nil, unsupportedError()
	}

	forwarding := handler.forwarding
	result, err := forwarding.HandleQuery(query)
	if forwarding.isClosed() {
		handler.deactivate(forwarding.terminalError())
	}

	return result, err
}

func (handler *deferredForwardingHandler) TerminalError() error {
	return handler.terminal
}

func (handler *deferredForwardingHandler) setQueryDecision(decision sqlpolicy.Decision) {
	handler.decision = decision
	if handler.forwarding != nil {
		handler.forwarding.setQueryDecision(decision)
	}
}

func (handler *deferredForwardingHandler) deactivate(err error) {
	handler.forwarding = nil
	handler.closed = true
	if handler.terminal == nil {
		handler.terminal = err
	}
}

var (
	_ server.Handler = (*deferredSessionHandler)(nil)
	_ server.Handler = (*deferredForwardingHandler)(nil)
)
