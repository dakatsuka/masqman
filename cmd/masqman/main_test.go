package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunLoadsAndValidatesConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "masqman.toml")
	if err := os.WriteFile(path, []byte("unknown = true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"-config", path}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unknown TOML keys") {
		t.Fatalf("stderr = %q, want config validation error", stderr.String())
	}
}

func TestRunStopsAfterValidConfigUntilStartupExists(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "masqman.toml")
	if err := os.WriteFile(path, []byte("environment = \"development\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"-config", path}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "startup is not implemented yet") {
		t.Fatalf("stderr = %q, want startup not implemented message", stderr.String())
	}
}

func TestRunPrintsVersion(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"-version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run exit code = %d, want 0", code)
	}
	if stdout.String() != "masqman dev\n" {
		t.Fatalf("stdout = %q, want version banner", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}
