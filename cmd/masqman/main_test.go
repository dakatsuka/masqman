package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
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
	httpAddr := freeLocalAddr(t)
	mysqlAddr := freeLocalAddr(t)
	cfg := config.Default()
	cfg.HTTP.ListenAddr = httpAddr
	cfg.MySQL.ListenAddr = mysqlAddr
	cfg.Audit.FilePath = auditPath

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- startMasqman(ctx, cfg)
	}()
	waitForHTTP(t, "http://"+httpAddr+"/login")
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

func TestStartMasqmanRejectsOccupiedHTTPListener(t *testing.T) {
	t.Parallel()

	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	cfg := config.Default()
	cfg.HTTP.ListenAddr = listener.Addr().String()
	cfg.MySQL.ListenAddr = freeLocalAddr(t)
	cfg.Audit.FilePath = filepath.Join(t.TempDir(), "audit.jsonl")

	err = startMasqman(context.Background(), cfg)
	if err == nil {
		t.Fatal("startMasqman() error = nil, want HTTP listener error")
	}
}

func TestMySQLCommandEndpointPreservesPublicHostForWildcardBind(t *testing.T) {
	t.Parallel()

	host, port := mysqlCommandEndpoint("0.0.0.0:3307")
	if host != "" || port != "3307" {
		t.Fatalf("mysqlCommandEndpoint wildcard = %q/%q, want empty host/3307", host, port)
	}

	host, port = mysqlCommandEndpoint("127.0.0.1:3307")
	if host != "127.0.0.1" || port != "3307" {
		t.Fatalf("mysqlCommandEndpoint loopback = %q/%q, want 127.0.0.1/3307", host, port)
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

func waitForHTTP(t *testing.T, url string) {
	t.Helper()

	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			t.Fatalf("NewRequestWithContext() error = %v", err)
		}
		response, err := client.Do(request)
		cancel()
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for HTTP listener %s", url)
}
