package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/config"
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

func TestRunStartsWithValidConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "masqman.toml")
	if err := os.WriteFile(path, []byte("environment = \"development\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var started config.Config
	code := runWithStarter(
		context.Background(),
		[]string{"-config", path},
		&stdout,
		&stderr,
		func(_ context.Context, cfg config.Config) error {
			started = cfg

			return nil
		},
	)

	if code != 0 {
		t.Fatalf("run exit code = %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if started.MySQL.ListenAddr == "" {
		t.Fatal("starter did not receive validated config")
	}
}

func TestRunReportsStartupError(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "masqman.toml")
	if err := os.WriteFile(path, []byte("environment = \"development\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	startErr := errors.New("listener failed")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithStarter(
		context.Background(),
		[]string{"-config", path},
		&stdout,
		&stderr,
		func(context.Context, config.Config) error {
			return startErr
		},
	)

	if code != 1 {
		t.Fatalf("run exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "startup: listener failed") {
		t.Fatalf("stderr = %q, want startup error", stderr.String())
	}
}

func TestStartMasqmanStopsOnContextCancellation(t *testing.T) {
	t.Parallel()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	mysqlAddr := freeLocalAddr(t)
	cfg := config.Default()
	cfg.MySQL.ListenAddr = mysqlAddr
	cfg.Audit.FilePath = auditPath

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- startMasqman(ctx, cfg)
	}()
	waitForTCP(t, mysqlAddr)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("startMasqman() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("startMasqman() did not stop after context cancellation")
	}
	if info, err := os.Stat(auditPath); err != nil {
		t.Fatalf("audit file missing after shutdown: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit file permissions = %v, want 0600", info.Mode().Perm())
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

func freeLocalAddr(t *testing.T) string {
	t.Helper()

	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	return listener.Addr().String()
}

func waitForTCP(t *testing.T, address string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		conn, err := new(net.Dialer).DialContext(ctx, "tcp", address)
		cancel()
		if err == nil {
			_ = conn.Close()

			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for TCP listener %s", address)
}
