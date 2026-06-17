package sqlpolicy_test

import (
	"testing"

	"github.com/dakatsuka/masqman/internal/sqlpolicy"
)

func TestClassifierAllowsConservativeReadQueries(t *testing.T) {
	t.Parallel()

	classifier := sqlpolicy.NewClassifier(sqlpolicy.Config{
		AllowedSchemas:    []string{"app"},
		AllowDefaultSetup: true,
	})

	for _, query := range []string{
		"select id, name from employees",
		"SELECT COUNT(*) FROM employees",
		"SELECT COUNT( * ) FROM employees",
		"SELECT COUNT(*) FROM employees GROUP BY id",
		"SELECT 1+1",
		"SELECT NOW()",
		"SELECT @@version LIMIT 1",
		"WITH recent AS (SELECT id FROM employees) SELECT id FROM recent",
	} {
		t.Run(query, func(t *testing.T) {
			t.Parallel()

			decision := classifier.Classify(query)
			if decision.Kind != sqlpolicy.AllowRead && decision.Kind != sqlpolicy.AllowOperationalRead {
				t.Fatalf("Classify(%q) = %#v, want allowed read", query, decision)
			}
		})
	}
}

func TestClassifierRejectsUnsafeStatements(t *testing.T) {
	t.Parallel()

	classifier := sqlpolicy.NewClassifier(sqlpolicy.Config{
		AllowedSchemas:    []string{"app"},
		AllowDefaultSetup: true,
	})

	for _, query := range []string{
		"insert into employees(id) values (1)",
		"select * from employees into outfile '/tmp/export'",
		"select * from employees for update",
		"select * from employees for share",
		"select * from information_schema.tables",
		"select * from `information_schema`.tables",
		"select * from mysql . user",
		"select * from performance_schema . events_statements_current",
		"select * from sys.schema_table_statistics",
		"select * from app.employees,information_schema.tables",
		"with tables as (select * from information_schema.tables) select * from tables",
		"show columns from employees",
		"show create table employees",
		"show tables from app",
		"describe employees",
		"select 1; select 2",
		"select '--'; drop table employees",
		"set global sql_log_bin = 0",
		"select sleep(10)",
		"select account()",
		"select discount(total) from invoices",
		"select id from employees where id in (select sleep(1))",
		"with x as (select sleep(1)) select * from x",
		"select database() from employees",
		"select count(1) from employees",
		"select count(`*`) from employees",
		"select count(email) from employees",
		"select count(distinct email) from employees",
		"select * from employees into/**/outfile '/tmp/export'",
		"select * from employees /*!80000 into outfile '/tmp/export'*/",
		"select id from employees /*!80000 union*/ select secret from employees",
		"select 1--1; drop table employees",
		"select id from employees union select secret from employees",
	} {
		t.Run(query, func(t *testing.T) {
			t.Parallel()

			decision := classifier.Classify(query)
			if decision.Kind != sqlpolicy.Reject {
				t.Fatalf("Classify(%q) = %#v, want reject", query, decision)
			}
		})
	}
}

func TestClassifierSeparatesSetupStatements(t *testing.T) {
	t.Parallel()

	classifier := sqlpolicy.NewClassifier(sqlpolicy.Config{
		AllowedSchemas:    []string{"app"},
		AllowDefaultSetup: true,
	})

	decision := classifier.Classify("SET NAMES utf8mb4")
	if decision.Kind != sqlpolicy.AllowSetup {
		t.Fatalf("Classify SET NAMES = %#v, want AllowSetup", decision)
	}

	decision = classifier.Classify("SET NAMES utf8mb4;")
	if decision.Kind != sqlpolicy.AllowSetup {
		t.Fatalf("Classify SET NAMES with semicolon = %#v, want AllowSetup", decision)
	}

	decision = classifier.Classify("SET character_set_results = utf8mb4;")
	if decision.Kind != sqlpolicy.AllowSetup {
		t.Fatalf("Classify SET character_set_results with semicolon = %#v, want AllowSetup", decision)
	}

	decision = classifier.Classify("SET character_set_results = utf8mb4, sql_mode = 'ANSI_QUOTES'")
	if decision.Kind != sqlpolicy.Reject {
		t.Fatalf("Classify combined SET = %#v, want Reject", decision)
	}

	decision = classifier.Classify("SET character_set_results = sleep(1)")
	if decision.Kind != sqlpolicy.Reject {
		t.Fatalf("Classify function SET = %#v, want Reject", decision)
	}

	decision = classifier.Classify("USE app")
	if decision.Kind != sqlpolicy.AllowSetup {
		t.Fatalf("Classify USE app = %#v, want AllowSetup", decision)
	}

	decision = classifier.Classify("USE app;")
	if decision.Kind != sqlpolicy.AllowSetup {
		t.Fatalf("Classify USE app with semicolon = %#v, want AllowSetup", decision)
	}

	decision = classifier.Classify("USE APP")
	if decision.Kind != sqlpolicy.Reject {
		t.Fatalf("Classify USE APP = %#v, want Reject", decision)
	}

	decision = classifier.Classify("USE `app;`")
	if decision.Kind != sqlpolicy.Reject {
		t.Fatalf("Classify USE quoted app semicolon = %#v, want Reject", decision)
	}

	decision = classifier.Classify("USE mysql")
	if decision.Kind != sqlpolicy.Reject {
		t.Fatalf("Classify USE mysql = %#v, want Reject", decision)
	}
}

func TestClassifierCanDisableDefaultSetupStatements(t *testing.T) {
	t.Parallel()

	classifier := sqlpolicy.NewClassifier(sqlpolicy.Config{AllowedSchemas: []string{"app"}})

	decision := classifier.Classify("SET NAMES utf8mb4")
	if decision.Kind != sqlpolicy.Reject {
		t.Fatalf("Classify SET NAMES with default setup disabled = %#v, want Reject", decision)
	}
}

func TestClassifierReturnsExpressionContext(t *testing.T) {
	t.Parallel()

	classifier := sqlpolicy.NewClassifier(sqlpolicy.Config{
		AllowedSchemas:    []string{"app"},
		AllowDefaultSetup: true,
	})

	decision := classifier.Classify("SELECT id, COUNT(*) FROM employees")
	if decision.Kind != sqlpolicy.AllowRead {
		t.Fatalf("Classify SELECT with COUNT(*) = %#v, want AllowRead", decision)
	}
	assertExpressionKinds(t, decision.ExpressionContext, []sqlpolicy.ExpressionKind{
		sqlpolicy.ExpressionColumn,
		sqlpolicy.ExpressionCountStar,
	})
	if decision.ExpressionContext[1].FunctionName != "count" || !decision.ExpressionContext[1].SafeBuiltin {
		t.Fatalf("COUNT(*) context = %#v, want safe count context", decision.ExpressionContext[1])
	}

	decision = classifier.Classify("SELECT 1")
	if decision.Kind != sqlpolicy.AllowOperationalRead {
		t.Fatalf("Classify SELECT 1 = %#v, want AllowOperationalRead", decision)
	}
	assertExpressionKinds(t, decision.ExpressionContext, []sqlpolicy.ExpressionKind{
		sqlpolicy.ExpressionLiteral,
	})
	if decision.ExpressionContext[0].SafeBuiltin {
		t.Fatalf("literal context = %#v, want SafeBuiltin false", decision.ExpressionContext[0])
	}

	decision = classifier.Classify("SELECT NOW()")
	if decision.Kind != sqlpolicy.AllowOperationalRead {
		t.Fatalf("Classify SELECT NOW() = %#v, want AllowOperationalRead", decision)
	}
	assertExpressionKinds(t, decision.ExpressionContext, []sqlpolicy.ExpressionKind{
		sqlpolicy.ExpressionSafeBuiltin,
	})
	if decision.ExpressionContext[0].FunctionName != "now" || !decision.ExpressionContext[0].SafeBuiltin {
		t.Fatalf("NOW() context = %#v, want safe builtin context", decision.ExpressionContext[0])
	}

	decision = classifier.Classify("SELECT @@global.version")
	if decision.Kind != sqlpolicy.AllowRead {
		t.Fatalf("Classify scoped variable read = %#v, want AllowRead", decision)
	}
	assertExpressionKinds(t, decision.ExpressionContext, []sqlpolicy.ExpressionKind{
		sqlpolicy.ExpressionUnknown,
	})
	if decision.ExpressionContext[0].SafeBuiltin {
		t.Fatalf("scoped variable context = %#v, want unsafe unknown context", decision.ExpressionContext[0])
	}

	decision = classifier.Classify("SELECT * FROM employees")
	if decision.Kind != sqlpolicy.AllowRead {
		t.Fatalf("Classify SELECT * = %#v, want AllowRead", decision)
	}
	if decision.ExpressionContext != nil {
		t.Fatalf("SELECT * expression contexts = %#v, want nil", decision.ExpressionContext)
	}
}

func assertExpressionKinds(
	t *testing.T,
	got []sqlpolicy.ExpressionContext,
	want []sqlpolicy.ExpressionKind,
) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("expression context length = %d, want %d: %#v", len(got), len(want), got)
	}
	for idx := range want {
		if got[idx].Kind != want[idx] {
			t.Fatalf("expression context[%d].Kind = %q, want %q: %#v", idx, got[idx].Kind, want[idx], got)
		}
	}
}
