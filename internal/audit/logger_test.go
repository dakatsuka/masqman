package audit_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/audit"
)

func TestNormalizeStatementRemovesSensitiveLiteralsAndComments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		statement string
		want      string
	}{
		{
			name:      "block and line comments",
			statement: "select /* hidden */ * from users where email = 'a@example.com' and id = 42 -- secret",
			want:      "select * from users where email = ? and id = ?",
		},
		{
			name:      "hash comment",
			statement: "select 1 # secret\nfrom users where id = 2",
			want:      "select ? from users where id = ?",
		},
		{
			name:      "hex literal",
			statement: "select * from users where token = 0xdeadbeef",
			want:      "select * from users where token = ?",
		},
		{
			name:      "dash operator is not comment",
			statement: "select 1--1; drop table employees",
			want:      "select ?--?; drop table employees",
		},
		{
			name:      "adjacent literals",
			statement: "select 'a''b', 1 2",
			want:      "select ?, ? ?",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := audit.NormalizeStatement(tc.statement)
			if got != tc.want {
				t.Fatalf("NormalizeStatement() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFileLoggerRotatesWhenConfiguredSizeIsExceeded(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewFileLoggerWithConfig(audit.FileConfig{
		Path:       path,
		MaxBytes:   1,
		MaxBackups: 1,
	})
	if err != nil {
		t.Fatalf("NewFileLoggerWithConfig returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := logger.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	for i := 0; i < 2; i++ {
		if err := logger.Log(context.Background(), audit.Event{
			Time:   time.Date(2026, 6, 16, 12, 0, i, 0, time.UTC),
			Kind:   audit.EventAuth,
			UserID: "alice",
		}); err != nil {
			t.Fatalf("Log %d returned error: %v", i, err)
		}
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated audit file missing: %v", err)
	}
}

func TestFileLoggerWritesJSONLinesWithOwnerOnlyPermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := logger.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	event := audit.Event{
		Time:                time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC),
		Kind:                audit.EventQuery,
		UserID:              "alice",
		NormalizedStatement: audit.NormalizeStatement("select * from employees where email = 'x'"),
		Decision:            "allow_read",
		MaskedFields:        2,
	}
	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("audit file permissions = %v, want %v", got, want)
	}

	// #nosec G304 -- test opens the audit file path created in t.TempDir.
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatalf("audit file has no lines: %v", scanner.Err())
	}

	var got audit.Event
	if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if got.UserID != "alice" || got.NormalizedStatement != "select * from employees where email = ?" {
		t.Fatalf("audit event = %#v", got)
	}
}

func TestFileLoggerFlushesBufferedFileState(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := logger.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	if err := logger.Log(context.Background(), audit.Event{
		Time:   time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC),
		Kind:   audit.EventAuth,
		UserID: "alice",
	}); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}

	if err := logger.Flush(); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
}
