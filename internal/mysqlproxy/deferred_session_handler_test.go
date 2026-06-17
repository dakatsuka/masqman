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
}
