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
		"SELECT NOW()",
		"SELECT @@version LIMIT 1",
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
		"select * from information_schema.tables",
		"select * from `information_schema`.tables",
		"select * from mysql . user",
		"select * from performance_schema . events_statements_current",
		"select * from sys.schema_table_statistics",
		"select * from app.employees,information_schema.tables",
		"show columns from employees",
		"select 1; select 2",
		"select '--'; drop table employees",
		"set global sql_log_bin = 0",
		"select sleep(10)",
		"select account()",
		"select discount(total) from invoices",
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
