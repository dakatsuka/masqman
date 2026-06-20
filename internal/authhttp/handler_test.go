package authhttp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/authhttp"
	"github.com/dakatsuka/masqman/internal/otp"
)

func TestLoginCreatesSessionWithoutIssuingCredential(t *testing.T) {
	t.Parallel()

	sessions := authhttp.NewSessionStore(authhttp.SessionConfig{TokenBytes: 16})
	provider := &recordingProvider{user: auth.User{ID: "alice", DisplayName: "Alice"}}
	issuer := &recordingIssuer{}
	handler := newTestHandler(t, authhttp.HandlerConfig{
		AuthProvider: provider,
		Sessions:     sessions,
		Issuer:       issuer,
		CookieSecure: true,
		MySQLHost:    "masqman.example.test",
	})

	loginResp := httptest.NewRecorder()
	handler.ServeHTTP(loginResp, newRequest(http.MethodGet, "/login", nil))
	if loginResp.Code != http.StatusOK {
		t.Fatalf("GET /login status = %d, want %d", loginResp.Code, http.StatusOK)
	}
	loginCSRF := findCookie(t, loginResp.Result(), "masqman_login_csrf")

	form := url.Values{
		"username":   {"alice"},
		"password":   {"secret"},
		"csrf_token": {loginCSRF.Value},
	}
	req := newRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(loginCSRF)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusSeeOther {
		t.Fatalf("POST /login status = %d, want %d", resp.Code, http.StatusSeeOther)
	}
	if location := resp.Header().Get("Location"); location != "/credentials" {
		t.Fatalf("Location = %q, want /credentials", location)
	}
	if provider.username != "alice" || provider.password != "secret" {
		t.Fatalf("provider credentials = %q/%q, want alice/secret", provider.username, provider.password)
	}
	if issuer.calls != 0 {
		t.Fatalf("issuer calls = %d, want 0", issuer.calls)
	}

	sessionCookie := findCookie(t, resp.Result(), "masqman_session")
	if !sessionCookie.HttpOnly {
		t.Fatal("session cookie is not HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Fatal("session cookie is not Secure")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite = %v, want Lax", sessionCookie.SameSite)
	}
	if _, ok := sessions.Get(sessionCookie.Value); !ok {
		t.Fatal("session cookie does not reference a live session")
	}
}

func TestLoginRejectsMissingCSRF(t *testing.T) {
	t.Parallel()

	provider := &recordingProvider{user: auth.User{ID: "alice"}}
	issuer := &recordingIssuer{}
	handler := newTestHandler(t, authhttp.HandlerConfig{
		AuthProvider: provider,
		Sessions:     authhttp.NewSessionStore(authhttp.SessionConfig{TokenBytes: 16}),
		Issuer:       issuer,
	})

	form := url.Values{"username": {"alice"}, "password": {"secret"}}
	req := newRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("POST /login status = %d, want %d", resp.Code, http.StatusForbidden)
	}
	if provider.username != "" {
		t.Fatalf("provider was called with username %q", provider.username)
	}
	if issuer.calls != 0 {
		t.Fatalf("issuer calls = %d, want 0", issuer.calls)
	}
}

func TestCredentialsRequireAuthenticatedSession(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, authhttp.HandlerConfig{
		AuthProvider: &recordingProvider{user: auth.User{ID: "alice"}},
		Sessions:     authhttp.NewSessionStore(authhttp.SessionConfig{TokenBytes: 16}),
		Issuer:       &recordingIssuer{},
	})

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, newRequest(http.MethodGet, "/credentials", nil))

	if resp.Code != http.StatusSeeOther {
		t.Fatalf("GET /credentials status = %d, want %d", resp.Code, http.StatusSeeOther)
	}
	if location := resp.Header().Get("Location"); location != "/login" {
		t.Fatalf("Location = %q, want /login", location)
	}
}

func TestCredentialIssuanceRequiresCSRFAndRendersPasswordSeparately(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 6, 20, 12, 30, 0, 0, time.UTC)
	sessions := authhttp.NewSessionStore(authhttp.SessionConfig{TokenBytes: 16})
	issuer := &recordingIssuer{credential: otp.Credential{
		Username:  "ot_alice",
		Password:  "separate-password",
		ExpiresAt: expiresAt,
	}}
	handler := newTestHandler(t, authhttp.HandlerConfig{
		AuthProvider: &recordingProvider{user: auth.User{ID: "alice"}},
		Sessions:     sessions,
		Issuer:       issuer,
		MySQLHost:    "masqman.example.test",
	})
	session, err := sessions.Create(auth.User{ID: "alice", DisplayName: "Alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	getReq := newRequest(http.MethodGet, "/credentials", nil)
	getReq.AddCookie(sessionRequestCookie(session.ID))
	getResp := httptest.NewRecorder()
	handler.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("GET /credentials status = %d, want %d", getResp.Code, http.StatusOK)
	}
	if !strings.Contains(getResp.Body.String(), `name="csrf_token" value="`+session.CSRFToken+`"`) {
		t.Fatalf("credential page did not render session CSRF token: %s", getResp.Body.String())
	}

	missingCSRFReq := newRequest(http.MethodPost, "/credentials", nil)
	missingCSRFReq.AddCookie(sessionRequestCookie(session.ID))
	missingCSRFResp := httptest.NewRecorder()
	handler.ServeHTTP(missingCSRFResp, missingCSRFReq)
	if missingCSRFResp.Code != http.StatusForbidden {
		t.Fatalf("POST /credentials without CSRF status = %d, want %d", missingCSRFResp.Code, http.StatusForbidden)
	}
	if issuer.calls != 0 {
		t.Fatalf("issuer calls after missing CSRF = %d, want 0", issuer.calls)
	}

	form := url.Values{"csrf_token": {session.CSRFToken}}
	req := newRequest(http.MethodPost, "/credentials", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionRequestCookie(session.ID))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("POST /credentials status = %d, want %d", resp.Code, http.StatusOK)
	}
	if issuer.calls != 1 {
		t.Fatalf("issuer calls = %d, want 1", issuer.calls)
	}
	if issuer.user.ID != "alice" || issuer.sessionID != session.ID {
		t.Fatalf("issuer got user/session = %#v/%q", issuer.user, issuer.sessionID)
	}
	body := resp.Body.String()
	if !strings.Contains(body, "mysql -h masqman.example.test -u ot_alice -p") {
		t.Fatalf("credential page did not render mysql command: %s", body)
	}
	if strings.Contains(body, "-pseparate-password") {
		t.Fatalf("credential page embedded password in mysql command: %s", body)
	}
	if !strings.Contains(body, "separate-password") {
		t.Fatalf("credential page did not render separate password: %s", body)
	}
}

func TestCredentialCommandIncludesConfiguredMySQLPort(t *testing.T) {
	t.Parallel()

	sessions := authhttp.NewSessionStore(authhttp.SessionConfig{TokenBytes: 16})
	issuer := &recordingIssuer{credential: otp.Credential{
		Username:  "ot_alice",
		Password:  "separate-password",
		ExpiresAt: time.Date(2026, 6, 20, 12, 30, 0, 0, time.UTC),
	}}
	handler := newTestHandler(t, authhttp.HandlerConfig{
		AuthProvider: &recordingProvider{user: auth.User{ID: "alice"}},
		Sessions:     sessions,
		Issuer:       issuer,
		MySQLHost:    "127.0.0.1",
		MySQLPort:    "3307",
	})
	session, err := sessions.Create(auth.User{ID: "alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	form := url.Values{"csrf_token": {session.CSRFToken}}
	req := newRequest(http.MethodPost, "/credentials", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionRequestCookie(session.ID))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("POST /credentials status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "mysql -h 127.0.0.1 -P 3307 -u ot_alice -p") {
		t.Fatalf("credential page did not render configured port: %s", resp.Body.String())
	}
}

func TestCredentialCommandUsesRequestHostWithoutHTTPPort(t *testing.T) {
	t.Parallel()

	sessions := authhttp.NewSessionStore(authhttp.SessionConfig{TokenBytes: 16})
	issuer := &recordingIssuer{credential: otp.Credential{
		Username:  "ot_alice",
		Password:  "separate-password",
		ExpiresAt: time.Date(2026, 6, 20, 12, 30, 0, 0, time.UTC),
	}}
	handler := newTestHandler(t, authhttp.HandlerConfig{
		AuthProvider: &recordingProvider{user: auth.User{ID: "alice"}},
		Sessions:     sessions,
		Issuer:       issuer,
		MySQLPort:    "3307",
	})
	session, err := sessions.Create(auth.User{ID: "alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	form := url.Values{"csrf_token": {session.CSRFToken}}
	req := newRequest(http.MethodPost, "/credentials", strings.NewReader(form.Encode()))
	req.Host = "masqman.example.test:8080"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionRequestCookie(session.ID))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("POST /credentials status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "mysql -h masqman.example.test -P 3307 -u ot_alice -p") {
		t.Fatalf("credential page did not render request host with MySQL port: %s", resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "masqman.example.test:8080") {
		t.Fatalf("credential page rendered HTTP port as MySQL host: %s", resp.Body.String())
	}
}

func TestInvalidCredentialCSRFDoesNotRefreshSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	sessions := authhttp.NewSessionStore(authhttp.SessionConfig{
		IdleLifetime:     time.Minute,
		AbsoluteLifetime: time.Hour,
		TokenBytes:       16,
		Now:              func() time.Time { return now },
	})
	issuer := &recordingIssuer{}
	handler := newTestHandler(t, authhttp.HandlerConfig{
		AuthProvider: &recordingProvider{user: auth.User{ID: "alice"}},
		Sessions:     sessions,
		Issuer:       issuer,
	})
	session, err := sessions.Create(auth.User{ID: "alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	now = now.Add(30 * time.Second)
	form := url.Values{"csrf_token": {"bad"}}
	req := newRequest(http.MethodPost, "/credentials", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionRequestCookie(session.ID))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("POST /credentials status = %d, want %d", resp.Code, http.StatusForbidden)
	}
	if issuer.calls != 0 {
		t.Fatalf("issuer calls = %d, want 0", issuer.calls)
	}

	now = now.Add(31 * time.Second)
	if _, ok := sessions.Get(session.ID); ok {
		t.Fatal("invalid CSRF request refreshed session idle lifetime")
	}
}

func TestLogoutDeletesSession(t *testing.T) {
	t.Parallel()

	sessions := authhttp.NewSessionStore(authhttp.SessionConfig{TokenBytes: 16})
	handler := newTestHandler(t, authhttp.HandlerConfig{
		AuthProvider: &recordingProvider{user: auth.User{ID: "alice"}},
		Sessions:     sessions,
		Issuer:       &recordingIssuer{},
	})
	session, err := sessions.Create(auth.User{ID: "alice"})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	form := url.Values{"csrf_token": {session.CSRFToken}}
	req := newRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionRequestCookie(session.ID))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusSeeOther {
		t.Fatalf("POST /logout status = %d, want %d", resp.Code, http.StatusSeeOther)
	}
	if location := resp.Header().Get("Location"); location != "/login" {
		t.Fatalf("Location = %q, want /login", location)
	}
	if _, ok := sessions.Get(session.ID); ok {
		t.Fatal("session remains live after logout")
	}
	cookie := findCookie(t, resp.Result(), "masqman_session")
	if cookie.MaxAge >= 0 {
		t.Fatalf("logout cookie MaxAge = %d, want deletion", cookie.MaxAge)
	}
}

func newTestHandler(t *testing.T, config authhttp.HandlerConfig) http.Handler {
	t.Helper()

	handler, err := authhttp.NewHandler(config)
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	return handler
}

func newRequest(method string, target string, body io.Reader) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), method, target, body)
}

func sessionRequestCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     "masqman_session",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

func findCookie(t *testing.T, response *http.Response, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}

	t.Fatalf("cookie %q not found in %#v", name, response.Cookies())

	return nil
}

type recordingProvider struct {
	user     auth.User
	err      error
	username string
	password string
}

func (p *recordingProvider) Authenticate(_ context.Context, username string, password string) (auth.User, error) {
	p.username = username
	p.password = password
	if p.err != nil {
		return auth.User{}, p.err
	}

	return p.user, nil
}

type recordingIssuer struct {
	credential otp.Credential
	err        error
	calls      int
	user       auth.User
	sessionID  string
}

func (i *recordingIssuer) Issue(_ context.Context, user auth.User, sessionID string) (otp.Credential, error) {
	i.calls++
	i.user = user
	i.sessionID = sessionID
	if i.err != nil {
		return otp.Credential{}, i.err
	}
	if i.credential.Username == "" {
		return otp.Credential{}, errors.New("test credential is not configured")
	}

	return i.credential, nil
}
