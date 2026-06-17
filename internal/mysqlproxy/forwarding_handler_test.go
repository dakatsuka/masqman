package mysqlproxy

import (
	"errors"
	"testing"

	"github.com/go-mysql-org/go-mysql/mysql"
)

func TestForwardingHandlerDelegatesQueryToUpstream(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{result: &mysql.Result{}}
	handler := newForwardingHandler(upstream)

	result, err := handler.HandleQuery("select id from employees")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}
	if result != upstream.result {
		t.Fatal("HandleQuery() did not return upstream result")
	}
	if upstream.query != "select id from employees" {
		t.Fatalf("upstream query = %q, want original query", upstream.query)
	}
}

func TestForwardingHandlerDelegatesInitDBToUpstream(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	handler := newForwardingHandler(upstream)

	if err := handler.UseDB("app"); err != nil {
		t.Fatalf("UseDB() error = %v, want nil", err)
	}
	if upstream.database != "app" {
		t.Fatalf("upstream database = %q, want app", upstream.database)
	}
}

func TestForwardingHandlerKeepsUpstreamOpenForMySQLError(t *testing.T) {
	t.Parallel()

	queryErr := mysql.NewError(mysql.ER_NO_SUCH_TABLE, "table missing")
	initDBErr := mysql.NewError(mysql.ER_BAD_DB_ERROR, "unknown database")
	upstream := &recordingUpstream{
		queryErr:  queryErr,
		initDBErr: initDBErr,
	}
	handler := newForwardingHandler(upstream)

	_, err := handler.HandleQuery("select id from employees")
	if !errors.Is(err, queryErr) {
		t.Fatalf("HandleQuery() error = %v, want %v", err, queryErr)
	}

	err = handler.UseDB("app")
	if !errors.Is(err, initDBErr) {
		t.Fatalf("UseDB() error = %v, want %v", err, initDBErr)
	}
	if upstream.closeCalls != 0 {
		t.Fatalf("upstream Close calls = %d, want 0", upstream.closeCalls)
	}
}

func TestForwardingHandlerClosesUpstreamOnNonMySQLError(t *testing.T) {
	t.Parallel()

	queryErr := errors.New("upstream packet read failed")
	upstream := &recordingUpstream{queryErr: queryErr}
	handler := newForwardingHandler(upstream)

	_, err := handler.HandleQuery("select id from employees")
	if !errors.Is(err, queryErr) {
		t.Fatalf("HandleQuery() error = %v, want %v", err, queryErr)
	}
	if upstream.closeCalls != 1 {
		t.Fatalf("upstream Close calls = %d, want 1", upstream.closeCalls)
	}
	if !errors.Is(handler.terminalError(), queryErr) {
		t.Fatalf("terminalError() = %v, want %v", handler.terminalError(), queryErr)
	}
}

func TestForwardingHandlerRejectsMultiResultAndClosesUpstream(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{
		result: &mysql.Result{Status: mysql.SERVER_MORE_RESULTS_EXISTS},
	}
	handler := newForwardingHandler(upstream)

	result, err := handler.HandleQuery("select id from employees")
	if result != nil {
		t.Fatalf("HandleQuery() result = %#v, want nil", result)
	}
	assertUnsupported(t, err)
	if !upstream.closed {
		t.Fatal("upstream was not closed after multi-result response")
	}
}

func TestForwardingHandlerRejectsUnsupportedProtocolSurface(t *testing.T) {
	t.Parallel()

	handler := newForwardingHandler(&recordingUpstream{})

	_, err := handler.HandleFieldList("employees", "%")
	assertUnsupported(t, err)

	_, _, _, err = handler.HandleStmtPrepare("select ?")
	assertUnsupported(t, err)

	_, err = handler.HandleStmtExecute(nil, "select ?", []any{1})
	assertUnsupported(t, err)

	assertUnsupported(t, handler.HandleStmtClose(nil))
	assertUnsupported(t, handler.HandleOtherCommand(mysql.COM_PROCESS_KILL, nil))
}

type recordingUpstream struct {
	database string
	query    string
	result   *mysql.Result
	events   *[]string

	initDBErr error
	queryErr  error
	closed    bool
	closeErr  error

	useDBCalls   int
	executeCalls int
	closeCalls   int
}

func (upstream *recordingUpstream) UseDB(database string) error {
	upstream.useDBCalls++
	upstream.database = database
	upstream.recordEvent("use_db:" + database)

	return upstream.initDBErr
}

func (upstream *recordingUpstream) Execute(query string, _ ...any) (*mysql.Result, error) {
	upstream.executeCalls++
	upstream.query = query
	upstream.recordEvent("execute:" + query)

	return upstream.result, upstream.queryErr
}

func (upstream *recordingUpstream) Close() error {
	upstream.closeCalls++
	upstream.closed = true
	upstream.recordEvent("close")

	return upstream.closeErr
}

func (upstream *recordingUpstream) recordEvent(event string) {
	if upstream.events != nil {
		*upstream.events = append(*upstream.events, event)
	}
}
