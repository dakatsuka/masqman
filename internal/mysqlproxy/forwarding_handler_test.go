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

func TestForwardingHandlerPropagatesUpstreamErrors(t *testing.T) {
	t.Parallel()

	queryErr := errors.New("upstream query failed")
	initDBErr := errors.New("upstream init db failed")
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

	initDBErr error
	queryErr  error
	closed    bool
	closeErr  error
}

func (upstream *recordingUpstream) UseDB(database string) error {
	upstream.database = database

	return upstream.initDBErr
}

func (upstream *recordingUpstream) Execute(query string, _ ...any) (*mysql.Result, error) {
	upstream.query = query

	return upstream.result, upstream.queryErr
}

func (upstream *recordingUpstream) Close() error {
	upstream.closed = true

	return upstream.closeErr
}
