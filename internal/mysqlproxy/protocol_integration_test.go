package mysqlproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/config"
	"github.com/dakatsuka/masqman/internal/masking"
	"github.com/dakatsuka/masqman/internal/otp"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
)

const dockerProtocolTestsEnv = "MASQMAN_RUN_DOCKER_PROTOCOL_TESTS"

var (
	dockerMySQLOnce   sync.Once
	dockerMySQLOutput string
	dockerMySQLErr    error
	dockerClientID    atomic.Uint64
	dockerRunID       = fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
)

func TestDockerProtocolAuthenticatesSetupSelectAndMasks(t *testing.T) {
	requireDockerProtocolTests(t)
	ensureDockerMySQL(t)

	store := otp.NewStore(config.Default().OTPStoreConfig())
	proxy := startDockerProtocolProxy(t, store)
	credential := issueDockerProtocolCredential(t, store, "alice", "auth-select")

	stdout, stderr, err := runMySQLClient(
		t,
		proxy.port,
		credential.Username,
		credential.Password,
		"SET NAMES utf8mb4; SELECT id, email FROM employees WHERE id = 1;",
	)
	if err != nil {
		t.Fatalf("mysql client error = %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	if got, want := strings.TrimSpace(stdout), "1\t***MASKED***"; got != want {
		t.Fatalf("mysql output = %q, want %q\nstderr:\n%s", got, want, stderr)
	}
}

func TestDockerProtocolFailedAuthDoesNotConsumeCredential(t *testing.T) {
	requireDockerProtocolTests(t)
	ensureDockerMySQL(t)

	store := otp.NewStore(config.Default().OTPStoreConfig())
	proxy := startDockerProtocolProxy(t, store)
	credential := issueDockerProtocolCredential(t, store, "alice", "auth-failure")

	_, stderr, err := runMySQLClient(t, proxy.port, credential.Username, "wrong-password", "SELECT 1;")
	if err == nil {
		t.Fatalf("mysql client with wrong password succeeded; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "ERROR 1045") && !strings.Contains(strings.ToLower(stderr), "access denied") {
		t.Fatalf("mysql client wrong-password stderr = %q, want access denied auth failure", stderr)
	}

	stdout, stderr, err := runMySQLClient(t, proxy.port, credential.Username, credential.Password, "SELECT 1;")
	if err != nil {
		t.Fatalf("mysql client with correct password error = %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if got, want := strings.TrimSpace(stdout), "1"; got != want {
		t.Fatalf("mysql output after failed auth = %q, want %q", got, want)
	}
}

func TestDockerProtocolRejectsMetadataQueries(t *testing.T) {
	requireDockerProtocolTests(t)
	ensureDockerMySQL(t)

	store := otp.NewStore(config.Default().OTPStoreConfig())
	proxy := startDockerProtocolProxy(t, store)
	credential := issueDockerProtocolCredential(t, store, "alice", "metadata")

	stdout, stderr, err := runMySQLClient(
		t,
		proxy.port,
		credential.Username,
		credential.Password,
		"SELECT table_name FROM information_schema.tables LIMIT 1;",
	)
	if err == nil {
		t.Fatalf("metadata query succeeded unexpectedly\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "ERROR 1227") {
		t.Fatalf("metadata query stderr = %q, want ERROR 1227", stderr)
	}
}

func TestDockerProtocolRejectsPreparedStatementCommand(t *testing.T) {
	requireDockerProtocolTests(t)
	ensureDockerMySQL(t)

	store := otp.NewStore(config.Default().OTPStoreConfig())
	proxy := startDockerProtocolProxy(t, store)
	credential := issueDockerProtocolCredential(t, store, "alice", "prepare")

	conn, err := client.Connect(
		proxy.hostPort(),
		credential.Username,
		credential.Password,
		"app",
	)
	if err != nil {
		t.Fatalf("go-mysql client connect error = %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	_, err = conn.Prepare("SELECT id FROM employees WHERE id = ?")
	assertMySQLErrorCode(t, err, mysql.ER_NOT_SUPPORTED_YET)
}

type dockerProtocolProxy struct {
	host string
	port int
}

func (proxy dockerProtocolProxy) hostPort() string {
	return net.JoinHostPort(proxy.host, strconv.Itoa(proxy.port))
}

func requireDockerProtocolTests(t *testing.T) {
	t.Helper()

	if os.Getenv(dockerProtocolTestsEnv) != "1" {
		t.Skipf("set %s=1 to run Docker Compose protocol tests", dockerProtocolTestsEnv)
	}
}

func ensureDockerMySQL(t *testing.T) {
	t.Helper()

	dockerMySQLOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		dockerMySQLOutput, dockerMySQLErr = dockerCompose(ctx, "up", "-d", "--wait", "mysql")
	})
	if dockerMySQLErr != nil {
		t.Fatalf("docker compose up mysql error = %v\n%s", dockerMySQLErr, dockerMySQLOutput)
	}
}

func startDockerProtocolProxy(t *testing.T, store *otp.Store) dockerProtocolProxy {
	t.Helper()

	// The Docker mysql client reaches this test proxy through host.docker.internal.
	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "0.0.0.0:0") //nolint:gosec
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	cfg := dockerProtocolConfig()
	cfg.MySQL.ListenAddr = listener.Addr().String()
	server, err := NewServer(cfg, store)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("NewServer() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		err := <-done
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("proxy Serve() error = %v", err)
		}
	})

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr = %T, want *net.TCPAddr", listener.Addr())
	}

	return dockerProtocolProxy{host: "127.0.0.1", port: addr.Port}
}

func dockerProtocolConfig() config.Config {
	cfg := config.Default()
	cfg.Upstream.Addr = "127.0.0.1:33060"
	cfg.Upstream.Database = "app"
	cfg.Upstream.Username = "masqman_proxy"
	cfg.Upstream.Password = "masqman_proxy_password"
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	cfg.Masking = masking.Config{
		TableRules: []masking.TableRule{{
			Schema:  "app",
			Table:   "employees",
			Columns: []string{"id"},
		}},
	}

	return cfg
}

func issueDockerProtocolCredential(
	t *testing.T,
	store *otp.Store,
	userID string,
	sessionID string,
) otp.Credential {
	t.Helper()

	credential, err := store.Issue(context.Background(), auth.User{ID: userID, DisplayName: userID}, sessionID)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	return credential
}

func runMySQLClient(
	t *testing.T,
	port int,
	username string,
	password string,
	query string,
) (string, string, error) {
	t.Helper()

	containerName := fmt.Sprintf("masqman-protocol-mysql-client-%s-%d", dockerRunID, dockerClientID.Add(1))
	t.Cleanup(func() {
		removeDockerContainer(containerName)
	})

	args := []string{
		"run",
		"--rm",
		"--no-deps",
		"--name",
		containerName,
		"mysql-client",
		"-hhost.docker.internal",
		fmt.Sprintf("-P%d", port),
		"--protocol=tcp",
		"--batch",
		"--raw",
		"--skip-column-names",
		"--connect-timeout=5",
		"--get-server-public-key",
		"-u" + username,
		"-p" + password,
		"-e",
		query,
		"app",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, args...)...) //nolint:gosec
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

func removeDockerContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", name) //nolint:gosec
	_ = cmd.Run()
}

func dockerCompose(ctx context.Context, args ...string) (string, error) {
	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, args...)...) //nolint:gosec
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()

	return output.String(), err
}
