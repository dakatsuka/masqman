package mysqlproxy

import (
	"errors"
	"testing"

	"github.com/go-mysql-org/go-mysql/mysql"
)

func TestDeferredSessionHandlerReplaysInitialDBOnActivation(t *testing.T) {
	t.Parallel()

	handler := newDeferredSessionHandler(testPolicyConfig())
	if err := handler.UseDB("app"); err != nil {
		t.Fatalf("UseDB() error = %v, want nil", err)
	}

	upstream := &recordingUpstream{}
	if err := handler.Activate(upstream); err != nil {
		t.Fatalf("Activate() error = %v, want nil", err)
	}
	if upstream.database != "app" {
		t.Fatalf("upstream database = %q, want app", upstream.database)
	}
}

func TestDeferredSessionHandlerAppliesPolicyBeforeActivation(t *testing.T) {
	t.Parallel()

	handler := newDeferredSessionHandler(testPolicyConfig())

	err := handler.UseDB("mysql")
	assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)

	_, err = handler.HandleQuery("drop table employees")
	assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)
}

func TestDeferredSessionHandlerDelegatesAfterActivation(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{result: &mysql.Result{}}
	handler := newDeferredSessionHandler(testPolicyConfig())
	if err := handler.Activate(upstream); err != nil {
		t.Fatalf("Activate() error = %v, want nil", err)
	}

	result, err := handler.HandleQuery("select id from employees")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}
	if result != upstream.result {
		t.Fatal("HandleQuery() did not return upstream result")
	}
	if upstream.query != "select id from employees" {
		t.Fatalf("upstream query = %q, want allowed query", upstream.query)
	}
}

func TestDeferredSessionHandlerClosesUpstreamWhenInitialDBReplayFails(t *testing.T) {
	t.Parallel()

	replayErr := errors.New("init db failed")
	upstream := &recordingUpstream{initDBErr: replayErr}
	handler := newDeferredSessionHandler(testPolicyConfig())
	if err := handler.UseDB("app"); err != nil {
		t.Fatalf("UseDB() error = %v, want nil", err)
	}

	err := handler.Activate(upstream)
	if !errors.Is(err, replayErr) {
		t.Fatalf("Activate() error = %v, want %v", err, replayErr)
	}
	if !upstream.closed {
		t.Fatal("upstream was not closed after initial DB replay failure")
	}
	if upstream.closeCalls != 1 {
		t.Fatalf("upstream Close calls = %d, want 1", upstream.closeCalls)
	}
}

func TestDeferredSessionHandlerClosesUpstreamOnceWhenInitialDBReplayConnectionFails(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{initDBErr: mysql.ErrBadConn}
	handler := newDeferredSessionHandler(testPolicyConfig())
	if err := handler.UseDB("app"); err != nil {
		t.Fatalf("UseDB() error = %v, want nil", err)
	}

	err := handler.Activate(upstream)
	if !errors.Is(err, mysql.ErrBadConn) {
		t.Fatalf("Activate() error = %v, want %v", err, mysql.ErrBadConn)
	}
	if upstream.closeCalls != 1 {
		t.Fatalf("upstream Close calls = %d, want 1", upstream.closeCalls)
	}
}

func TestDeferredSessionHandlerDoesNotReuseUpstreamAfterMultiResult(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: &mysql.Result{Status: mysql.SERVER_MORE_RESULTS_EXISTS},
	}
	handler := newDeferredSessionHandler(testPolicyConfig())
	if err := handler.Activate(upstream); err != nil {
		t.Fatalf("Activate() error = %v, want nil", err)
	}

	_, err := handler.HandleQuery("select id from employees")
	assertUnsupported(t, err)

	_, err = handler.HandleQuery("select id from employees")
	assertUnsupported(t, err)

	if upstream.executeCalls != 1 {
		t.Fatalf("upstream Execute calls = %d, want 1", upstream.executeCalls)
	}
	if upstream.closeCalls != 1 {
		t.Fatalf("upstream Close calls = %d, want 1", upstream.closeCalls)
	}
}

func TestDeferredSessionHandlerTerminatesAfterUpstreamProtocolError(t *testing.T) {
	t.Parallel()

	queryErr := errors.New("upstream packet read failed")
	upstream := &recordingUpstream{queryErr: queryErr}
	handler := newDeferredSessionHandler(testPolicyConfig())
	if err := handler.Activate(upstream); err != nil {
		t.Fatalf("Activate() error = %v, want nil", err)
	}

	_, err := handler.HandleQuery("select id from employees")
	if !errors.Is(err, queryErr) {
		t.Fatalf("HandleQuery() error = %v, want %v", err, queryErr)
	}
	if !errors.Is(handler.TerminalError(), queryErr) {
		t.Fatalf("TerminalError() = %v, want %v", handler.TerminalError(), queryErr)
	}

	_, err = handler.HandleQuery("select id from employees")
	assertUnsupported(t, err)

	if upstream.executeCalls != 1 {
		t.Fatalf("upstream Execute calls = %d, want 1", upstream.executeCalls)
	}
	if upstream.closeCalls != 1 {
		t.Fatalf("upstream Close calls = %d, want 1", upstream.closeCalls)
	}
}

func TestDeferredSessionHandlerKeepsUpstreamOpenForMySQLError(t *testing.T) {
	t.Parallel()

	mysqlErr := mysql.NewError(mysql.ER_NO_SUCH_TABLE, "table missing")
	upstream := &recordingUpstream{queryErr: mysqlErr}
	handler := newDeferredSessionHandler(testPolicyConfig())
	if err := handler.Activate(upstream); err != nil {
		t.Fatalf("Activate() error = %v, want nil", err)
	}

	_, err := handler.HandleQuery("select id from employees")
	if !errors.Is(err, mysqlErr) {
		t.Fatalf("HandleQuery() error = %v, want %v", err, mysqlErr)
	}

	_, err = handler.HandleQuery("select id from employees")
	if !errors.Is(err, mysqlErr) {
		t.Fatalf("HandleQuery() error = %v, want %v", err, mysqlErr)
	}

	if handler.TerminalError() != nil {
		t.Fatalf("TerminalError() = %v, want nil", handler.TerminalError())
	}
	if upstream.executeCalls != 2 {
		t.Fatalf("upstream Execute calls = %d, want 2", upstream.executeCalls)
	}
	if upstream.closeCalls != 0 {
		t.Fatalf("upstream Close calls = %d, want 0", upstream.closeCalls)
	}
}
