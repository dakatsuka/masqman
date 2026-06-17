package mysqlproxy

import (
	"testing"

	"github.com/go-mysql-org/go-mysql/mysql"
)

func TestSessionHandlerAppliesPolicyBeforeForwarding(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{result: &mysql.Result{}}
	handler := newSessionHandler(testPolicyConfig(), upstream)

	result, err := handler.HandleQuery("select id from employees")
	if err != nil {
		t.Fatalf("HandleQuery(allowed) error = %v, want nil", err)
	}
	if result != upstream.result {
		t.Fatal("HandleQuery(allowed) did not return upstream result")
	}
	if upstream.query != "select id from employees" {
		t.Fatalf("upstream query = %q, want allowed query", upstream.query)
	}

	_, err = handler.HandleQuery("drop table employees")
	assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)
	if upstream.query != "select id from employees" {
		t.Fatalf("upstream query after rejection = %q, want unchanged allowed query", upstream.query)
	}
}

func TestSessionHandlerAppliesSchemaPolicyBeforeInitDB(t *testing.T) {
	t.Parallel()

	upstream := &recordingUpstream{}
	handler := newSessionHandler(testPolicyConfig(), upstream)

	if err := handler.UseDB("app"); err != nil {
		t.Fatalf("UseDB(allowed) error = %v, want nil", err)
	}
	if upstream.database != "app" {
		t.Fatalf("upstream database = %q, want app", upstream.database)
	}

	err := handler.UseDB("mysql")
	assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)
	if upstream.database != "app" {
		t.Fatalf("upstream database after rejection = %q, want unchanged app", upstream.database)
	}
}
