package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/config"
	"github.com/dakatsuka/masqman/internal/masking"
)

const dockerE2ETestsEnv = "MASQMAN_RUN_DOCKER_PROTOCOL_TESTS"

var (
	e2eDockerMySQLOnce   sync.Once
	e2eDockerMySQLOutput string
	e2eDockerMySQLErr    error
	e2eDockerClientID    atomic.Uint64
	e2eDockerRunID       = fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	csrfTokenPattern     = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	mysqlCommandPattern  = regexp.MustCompile(`mysql -h [^ ]+ -P ([0-9]+) -u ([^ ]+) -p`)
	passwordPattern      = regexp.MustCompile(`<code>([^<]+)</code>`)
)

func TestDockerE2EHTTPIssuedCredentialConnectsToMySQLProxy(t *testing.T) {
	requireDockerE2ETests(t)
	ensureE2EDockerMySQL(t)

	httpAddr := freeLocalAddr(t)
	mysqlAddr, mysqlPort := freeWildcardAddr(t)
	cfg := dockerE2EConfig(t, httpAddr, mysqlAddr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- startMasqman(ctx, cfg)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("startMasqman() cleanup error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("startMasqman() did not stop during cleanup")
		}
	})
	waitForHTTP(t, "http://"+httpAddr+"/login")
	waitForTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(mysqlPort)))

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	loginCSRF := getLoginCSRF(t, client, httpAddr)
	sessionCookie := postLogin(t, client, httpAddr, loginCSRF)
	sessionCSRF := getSessionCSRF(t, client, httpAddr, sessionCookie)
	username, password := postCredential(t, client, httpAddr, sessionCookie, sessionCSRF, mysqlPort)

	stdout, stderr, err := runE2EMySQLClient(
		t,
		mysqlPort,
		username,
		password,
		"SET NAMES utf8mb4; SELECT id, email FROM employees WHERE id = 1;",
	)
	if err != nil {
		t.Fatalf("mysql client error = %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if got, want := strings.TrimSpace(stdout), "1\t***MASKED***"; got != want {
		t.Fatalf("mysql output = %q, want %q\nstderr:\n%s", got, want, stderr)
	}
}

func requireDockerE2ETests(t *testing.T) {
	t.Helper()

	if os.Getenv(dockerE2ETestsEnv) != "1" {
		t.Skipf("set %s=1 to run Docker end-to-end tests", dockerE2ETestsEnv)
	}
}

func ensureE2EDockerMySQL(t *testing.T) {
	t.Helper()

	e2eDockerMySQLOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		e2eDockerMySQLOutput, e2eDockerMySQLErr = e2eDockerCompose(ctx, "up", "-d", "--wait", "mysql")
	})
	if e2eDockerMySQLErr != nil {
		t.Fatalf("docker compose up mysql error = %v\n%s", e2eDockerMySQLErr, e2eDockerMySQLOutput)
	}
}

func dockerE2EConfig(t *testing.T, httpAddr string, mysqlAddr string) config.Config {
	t.Helper()

	cfg := config.Default()
	cfg.HTTP.ListenAddr = httpAddr
	cfg.MySQL.ListenAddr = mysqlAddr
	cfg.Upstream.Addr = "127.0.0.1:33060"
	cfg.Upstream.Database = "app"
	cfg.Upstream.Username = "masqman_proxy"
	cfg.Upstream.Password = "masqman_proxy_password"
	cfg.Auth.LocalUsers = []auth.LocalUser{{
		Username:    "alice",
		Password:    "secret",
		DisplayName: "Alice",
	}}
	cfg.Setup.AllowSchemaSelection = []string{"app"}
	cfg.Masking = masking.Config{
		TableRules: []masking.TableRule{{
			Schema:  "app",
			Table:   "employees",
			Columns: []string{"id"},
		}},
	}
	cfg.Audit.FilePath = filepath.Join(t.TempDir(), "audit.jsonl")

	return cfg
}

func getLoginCSRF(t *testing.T, client *http.Client, httpAddr string) *http.Cookie {
	t.Helper()

	response := doHTTPRequest(t, client, http.MethodGet, "http://"+httpAddr+"/login", nil, nil)
	defer closeBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /login status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	return responseCookie(t, response, "masqman_login_csrf")
}

func postLogin(t *testing.T, client *http.Client, httpAddr string, loginCSRF *http.Cookie) *http.Cookie {
	t.Helper()

	form := url.Values{
		"username":   {"alice"},
		"password":   {"secret"},
		"csrf_token": {loginCSRF.Value},
	}
	response := doHTTPRequest(t, client, http.MethodPost, "http://"+httpAddr+"/login", form, []*http.Cookie{loginCSRF})
	defer closeBody(t, response)
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /login status = %d, want %d", response.StatusCode, http.StatusSeeOther)
	}
	if location := response.Header.Get("Location"); location != "/credentials" {
		t.Fatalf("POST /login Location = %q, want /credentials", location)
	}

	return responseCookie(t, response, "masqman_session")
}

func getSessionCSRF(t *testing.T, client *http.Client, httpAddr string, sessionCookie *http.Cookie) string {
	t.Helper()

	response := doHTTPRequest(
		t,
		client,
		http.MethodGet,
		"http://"+httpAddr+"/credentials",
		nil,
		[]*http.Cookie{sessionCookie},
	)
	defer closeBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /credentials status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	return extractMatch(t, readBody(t, response), csrfTokenPattern, "session CSRF token")
}

func postCredential(
	t *testing.T,
	client *http.Client,
	httpAddr string,
	sessionCookie *http.Cookie,
	sessionCSRF string,
	mysqlPort int,
) (string, string) {
	t.Helper()

	form := url.Values{"csrf_token": {sessionCSRF}}
	response := doHTTPRequest(
		t,
		client,
		http.MethodPost,
		"http://"+httpAddr+"/credentials",
		form,
		[]*http.Cookie{sessionCookie},
	)
	defer closeBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST /credentials status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	body := readBody(t, response)
	commandMatch := mysqlCommandPattern.FindStringSubmatch(body)
	if len(commandMatch) != 3 {
		t.Fatalf("credential page did not render mysql command: %s", body)
	}
	if commandMatch[1] != strconv.Itoa(mysqlPort) {
		t.Fatalf("credential command port = %q, want %d", commandMatch[1], mysqlPort)
	}
	password := extractMatch(t, body, passwordPattern, "credential password")
	if strings.Contains(body, "-p"+password) {
		t.Fatalf("credential page embedded password in mysql command: %s", body)
	}

	return commandMatch[2], password
}

func doHTTPRequest(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	form url.Values,
	cookies []*http.Cookie,
) *http.Response {
	t.Helper()

	var body *strings.Reader
	if form == nil {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s error = %v", method, url, err)
	}

	return response
}

func responseCookie(t *testing.T, response *http.Response, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}

	t.Fatalf("cookie %q not found in %#v", name, response.Cookies())

	return nil
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()

	var body bytes.Buffer
	if _, err := body.ReadFrom(response.Body); err != nil {
		t.Fatalf("ReadFrom response body error = %v", err)
	}

	return body.String()
}

func closeBody(t *testing.T, response *http.Response) {
	t.Helper()

	if err := response.Body.Close(); err != nil {
		t.Fatalf("response body Close() error = %v", err)
	}
}

func extractMatch(t *testing.T, body string, pattern *regexp.Regexp, label string) string {
	t.Helper()

	match := pattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("%s not found in body: %s", label, body)
	}

	return match[1]
}

func freeWildcardAddr(t *testing.T) (string, int) {
	t.Helper()

	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "0.0.0.0:0") //nolint:gosec
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr = %T, want *net.TCPAddr", listener.Addr())
	}

	return net.JoinHostPort("0.0.0.0", strconv.Itoa(addr.Port)), addr.Port
}

func runE2EMySQLClient(
	t *testing.T,
	port int,
	username string,
	password string,
	query string,
) (string, string, error) {
	t.Helper()

	containerName := fmt.Sprintf("masqman-e2e-mysql-client-%s-%d", e2eDockerRunID, e2eDockerClientID.Add(1))
	t.Cleanup(func() {
		removeE2EDockerContainer(containerName)
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

func removeE2EDockerContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", name) //nolint:gosec
	_ = cmd.Run()
}

func e2eDockerCompose(ctx context.Context, args ...string) (string, error) {
	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, args...)...) //nolint:gosec
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()

	return output.String(), err
}
