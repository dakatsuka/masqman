package mysqlproxy

import (
	"testing"

	"github.com/dakatsuka/masqman/internal/sqlpolicy"

	"github.com/go-mysql-org/go-mysql/mysql"
)

func TestPolicyHandlerDelegatesAllowedQueries(t *testing.T) {
	t.Parallel()

	next := &recordingHandler{}
	handler := newPolicyHandler(testPolicyConfig(), next)

	result, err := handler.HandleQuery("select id from employees")
	if err != nil {
		t.Fatalf("HandleQuery() error = %v, want nil", err)
	}
	if result != next.result {
		t.Fatal("HandleQuery() did not return delegated result")
	}
	if next.query != "select id from employees" {
		t.Fatalf("delegated query = %q, want original query", next.query)
	}
}

func TestPolicyHandlerRejectsUnsafeQueriesWithoutDelegating(t *testing.T) {
	t.Parallel()

	next := &recordingHandler{}
	handler := newPolicyHandler(testPolicyConfig(), next)

	_, err := handler.HandleQuery("drop table employees")
	assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)
	if next.query != "" {
		t.Fatalf("delegated query = %q, want no delegation", next.query)
	}
}

func TestPolicyHandlerClassifiesInitDB(t *testing.T) {
	t.Parallel()

	next := &recordingHandler{}
	handler := newPolicyHandler(testPolicyConfig(), next)

	if err := handler.UseDB("app"); err != nil {
		t.Fatalf("UseDB(allowed) error = %v, want nil", err)
	}
	if next.database != "app" {
		t.Fatalf("delegated database = %q, want app", next.database)
	}

	err := handler.UseDB("mysql")
	assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)
	if next.database != "app" {
		t.Fatalf("delegated database after rejection = %q, want unchanged app", next.database)
	}
}

func TestPolicyHandlerRejectsInitDBNamesWithSQLSyntax(t *testing.T) {
	t.Parallel()

	for _, database := range []string{
		"APP",
		"app -- comment",
		"app # comment",
		"app /* comment */",
		"`app`",
	} {
		t.Run(database, func(t *testing.T) {
			t.Parallel()

			next := &recordingHandler{}
			handler := newPolicyHandler(testPolicyConfig(), next)

			err := handler.UseDB(database)
			assertMySQLErrorCode(t, err, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR)
			if next.database != "" {
				t.Fatalf("delegated database = %q, want no delegation", next.database)
			}
		})
	}
}

func testPolicyConfig() sqlpolicy.Config {
	return sqlpolicy.Config{
		AllowedSchemas:    []string{"app"},
		AllowDefaultSetup: true,
	}
}

type recordingHandler struct {
	unsupportedHandler

	database string
	query    string
	result   *mysql.Result
}

func (handler *recordingHandler) UseDB(database string) error {
	handler.database = database

	return nil
}

func (handler *recordingHandler) HandleQuery(query string) (*mysql.Result, error) {
	handler.query = query
	if handler.result == nil {
		handler.result = &mysql.Result{}
	}

	return handler.result, nil
}
