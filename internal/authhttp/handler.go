package authhttp

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/otp"
)

const (
	sessionCookieName   = "masqman_session"
	loginCSRFCookieName = "masqman_login_csrf"
	csrfFormField       = "csrf_token"
)

var (
	// ErrInvalidHandlerConfig reports a missing dependency for browser routes.
	ErrInvalidHandlerConfig = errors.New("invalid auth http handler config")

	loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Masqman Login</title></head>
<body>
<main>
<h1>Masqman</h1>
<form method="post" action="/login">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form>
</main>
</body>
</html>
`))

	credentialsTemplate = template.Must(template.New("credentials").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Masqman Credentials</title></head>
<body>
<main>
<h1>MySQL credentials</h1>
<form method="post" action="/credentials">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<button type="submit">Issue credential</button>
</form>
{{if .Credential}}
<section>
<h2>Issued credential</h2>
<pre>{{.Credential.Command}}</pre>
<dl>
<dt>Password</dt><dd><code>{{.Credential.Password}}</code></dd>
<dt>Expires</dt><dd><time datetime="{{.Credential.ExpiresAt}}">{{.Credential.ExpiresAt}}</time></dd>
</dl>
</section>
{{end}}
<form method="post" action="/logout">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<button type="submit">Sign out</button>
</form>
</main>
</body>
</html>
`))
)

// HandlerConfig wires browser authentication routes to local session and
// one-time credential services.
type HandlerConfig struct {
	AuthProvider auth.FlowProvider
	Sessions     *SessionStore
	Issuer       otp.Issuer
	CookieSecure bool
	MySQLHost    string
	TokenBytes   int
	Random       io.Reader
}

// Handler serves the browser login and one-time credential routes.
type Handler struct {
	authProvider auth.FlowProvider
	sessions     *SessionStore
	issuer       otp.Issuer
	cookieSecure bool
	mysqlHost    string
	tokenBytes   int
	random       io.Reader
}

type loginPageData struct {
	CSRFToken string
}

type credentialsPageData struct {
	CSRFToken  string
	Credential *credentialView
}

type credentialView struct {
	Command   string
	Password  string
	ExpiresAt string
}

// NewHandler creates browser authentication routes.
func NewHandler(config HandlerConfig) (*Handler, error) {
	if config.AuthProvider == nil {
		return nil, fmt.Errorf("%w: auth provider is required", ErrInvalidHandlerConfig)
	}
	if config.Sessions == nil {
		return nil, fmt.Errorf("%w: session store is required", ErrInvalidHandlerConfig)
	}
	if config.Issuer == nil {
		return nil, fmt.Errorf("%w: credential issuer is required", ErrInvalidHandlerConfig)
	}
	if config.TokenBytes <= 0 {
		config.TokenBytes = 32
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}

	return &Handler{
		authProvider: config.AuthProvider,
		sessions:     config.Sessions,
		issuer:       config.Issuer,
		cookieSecure: config.CookieSecure,
		mysqlHost:    config.MySQLHost,
		tokenBytes:   config.TokenBytes,
		random:       config.Random,
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		http.Redirect(w, r, "/credentials", http.StatusSeeOther)
	case r.URL.Path == "/login" && r.Method == http.MethodGet:
		h.handleLoginGet(w)
	case r.URL.Path == "/login" && r.Method == http.MethodPost:
		h.handleLoginPost(w, r)
	case r.URL.Path == "/credentials" && r.Method == http.MethodGet:
		h.handleCredentialsGet(w, r)
	case r.URL.Path == "/credentials" && r.Method == http.MethodPost:
		h.handleCredentialsPost(w, r)
	case r.URL.Path == "/logout" && r.Method == http.MethodPost:
		h.handleLogoutPost(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleLoginGet(w http.ResponseWriter) {
	csrfToken, err := randomToken(h.random, h.tokenBytes)
	if err != nil {
		http.Error(w, "login unavailable", http.StatusInternalServerError)

		return
	}
	h.setCookie(w, loginCSRFCookieName, csrfToken, "/login")
	renderHTML(w, loginTemplate, loginPageData{CSRFToken: csrfToken})
}

func (h *Handler) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)

		return
	}
	if !h.validateLoginCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)

		return
	}

	user, err := h.authProvider.Authenticate(
		r.Context(),
		r.PostForm.Get("username"),
		r.PostForm.Get("password"),
	)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)

		return
	}

	session, err := h.sessions.Create(user)
	if err != nil {
		http.Error(w, "login unavailable", http.StatusInternalServerError)

		return
	}

	h.setCookie(w, sessionCookieName, session.ID, "/")
	h.clearCookie(w, loginCSRFCookieName, "/login")
	http.Redirect(w, r, "/credentials", http.StatusSeeOther)
}

func (h *Handler) handleCredentialsGet(w http.ResponseWriter, r *http.Request) {
	session, ok := h.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)

		return
	}

	renderHTML(w, credentialsTemplate, credentialsPageData{CSRFToken: session.CSRFToken})
}

func (h *Handler) handleCredentialsPost(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := h.sessionID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)

		return
	}
	if !h.validateSessionCSRF(r, sessionID) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)

		return
	}
	session, ok := h.sessions.Get(sessionID)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)

		return
	}

	credential, err := h.issuer.Issue(r.Context(), session.User, session.ID)
	if err != nil {
		if errors.Is(err, otp.ErrIssuanceRateLimited) {
			http.Error(w, "credential issuance rate limited", http.StatusTooManyRequests)

			return
		}
		http.Error(w, "credential issuance failed", http.StatusInternalServerError)

		return
	}

	renderHTML(w, credentialsTemplate, credentialsPageData{
		CSRFToken: session.CSRFToken,
		Credential: &credentialView{
			Command:   fmt.Sprintf("mysql -h %s -u %s -p", h.hostForCommand(r), credential.Username),
			Password:  credential.Password,
			ExpiresAt: credential.ExpiresAt.Format(time.RFC3339),
		},
	})
}

func (h *Handler) handleLogoutPost(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := h.sessionID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)

		return
	}
	if !h.validateSessionCSRF(r, sessionID) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)

		return
	}
	session, ok := h.sessions.Get(sessionID)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)

		return
	}

	h.sessions.Delete(session.ID)
	h.clearCookie(w, sessionCookieName, "/")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) currentSession(r *http.Request) (Session, bool) {
	sessionID, ok := h.sessionID(r)
	if !ok {
		return Session{}, false
	}

	return h.sessions.Get(sessionID)
}

func (h *Handler) sessionID(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}

	return cookie.Value, true
}

func (h *Handler) validateLoginCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(loginCSRFCookieName)
	if err != nil {
		return false
	}

	return constantTimeEqual(cookie.Value, r.PostForm.Get(csrfFormField))
}

func (h *Handler) validateSessionCSRF(r *http.Request, sessionID string) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}

	return h.sessions.ValidateCSRF(sessionID, r.PostForm.Get(csrfFormField))
}

func (h *Handler) hostForCommand(r *http.Request) string {
	if h.mysqlHost != "" {
		return h.mysqlHost
	}

	return r.Host
}

func (h *Handler) setCookie(w http.ResponseWriter, name string, value string, path string) {
	//nolint:gosec // Production config sets CookieSecure; development HTTP listeners may use plaintext.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter, name string, path string) {
	//nolint:gosec // Production config sets CookieSecure; development HTTP listeners may use plaintext.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func constantTimeEqual(left string, right string) bool {
	if left == "" || right == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func renderHTML(w http.ResponseWriter, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "template rendering failed", http.StatusInternalServerError)
	}
}
