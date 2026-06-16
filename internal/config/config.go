// Package config loads and validates Masqman's TOML configuration.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/masking"
)

// ErrInvalid wraps configuration validation failures.
var ErrInvalid = errors.New("invalid config")

// Environment identifies whether production-only safety checks apply.
type Environment string

const (
	// EnvironmentDevelopment permits insecure local listeners.
	EnvironmentDevelopment Environment = "development"
	// EnvironmentProduction requires TLS on browser and MySQL listeners.
	EnvironmentProduction Environment = "production"
)

// Config is the root Masqman TOML configuration.
type Config struct {
	Environment Environment    `toml:"environment"`
	HTTP        Listener       `toml:"http"`
	MySQL       Listener       `toml:"mysql"`
	Upstream    Upstream       `toml:"upstream"`
	Auth        Auth           `toml:"auth"`
	OTP         OTP            `toml:"otp"`
	Sessions    Sessions       `toml:"sessions"`
	RateLimits  RateLimits     `toml:"rate_limits"`
	Setup       Setup          `toml:"setup"`
	Masking     masking.Config `toml:"masking"`
	Secrets     Secrets        `toml:"secrets"`
	Audit       Audit          `toml:"audit"`
}

// Listener configures one inbound TCP listener and optional TLS.
type Listener struct {
	ListenAddr string `toml:"listen_addr"`
	TLS        TLS    `toml:"tls"`
}

// TLS contains listener TLS settings.
type TLS struct {
	Enabled  bool   `toml:"enabled"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

// Upstream configures Masqman's dedicated read-only MySQL account.
type Upstream struct {
	Addr          string `toml:"addr"`
	Database      string `toml:"database"`
	Username      string `toml:"username"`
	Password      string `toml:"password"`
	TLSEnabled    bool   `toml:"tls_enabled"`
	TLSCAFile     string `toml:"tls_ca_file"`
	TLSServerName string `toml:"tls_server_name"`
	TLSSkipVerify bool   `toml:"tls_skip_verify"`
}

// Auth configures browser authentication providers.
type Auth struct {
	LocalUsers []auth.LocalUser `toml:"local_users"`
}

// OTP configures one-time MySQL credential issuance.
type OTP struct {
	TTL                 time.Duration `toml:"ttl"`
	UsernameEntropyBits int           `toml:"username_entropy_bits"`
	PasswordEntropyBits int           `toml:"password_entropy_bits"`
}

// Sessions controls browser and MySQL session lifetimes.
type Sessions struct {
	BrowserIdleTimeout    time.Duration `toml:"browser_idle_timeout"`
	BrowserAbsoluteLimit  time.Duration `toml:"browser_absolute_limit"`
	MySQLIdleTimeout      time.Duration `toml:"mysql_idle_timeout"`
	MySQLMaxDuration      time.Duration `toml:"mysql_max_duration"`
	ShutdownDrainDeadline time.Duration `toml:"shutdown_drain_deadline"`
}

// RateLimits controls default authentication and resource limits.
type RateLimits struct {
	CredentialFailures             int           `toml:"credential_failures"`
	SourceFailures                 int           `toml:"source_failures"`
	FailureWindow                  time.Duration `toml:"failure_window"`
	CredentialIssuanceUserLimit    int           `toml:"credential_issuance_user_limit"`
	CredentialIssuanceSessionLimit int           `toml:"credential_issuance_session_limit"`
	CredentialIssuanceWindow       time.Duration `toml:"credential_issuance_window"`
	MaxMySQLSessions               int           `toml:"max_mysql_sessions"`
	MaxQueryBytes                  int           `toml:"max_query_bytes"`
	MaxResultRows                  int           `toml:"max_result_rows"`
	MaxResultBytes                 int64         `toml:"max_result_bytes"`
}

// Setup configures M1 setup-statement and schema-selection policy surfaces.
type Setup struct {
	AllowSchemaSelection []string `toml:"allow_schema_selection"`
	AllowDefaultSetup    bool     `toml:"allow_default_setup"`
}

// Secrets configures production secret references outside the main TOML file.
type Secrets struct {
	UpstreamPasswordEnv  string `toml:"upstream_password_env"`
	UpstreamPasswordFile string `toml:"upstream_password_file"`
}

// Audit configures the initial file audit sink.
type Audit struct {
	FilePath   string `toml:"file_path"`
	MaxBytes   int64  `toml:"max_bytes"`
	MaxBackups int    `toml:"max_backups"`
}

// Default returns a development configuration populated with M1 defaults.
func Default() Config {
	return Config{
		Environment: EnvironmentDevelopment,
		HTTP:        Listener{ListenAddr: "127.0.0.1:8080"},
		MySQL:       Listener{ListenAddr: "127.0.0.1:3307"},
		OTP: OTP{
			TTL:                 10 * time.Minute,
			UsernameEntropyBits: 96,
			PasswordEntropyBits: 192,
		},
		Sessions: Sessions{
			BrowserIdleTimeout:    30 * time.Minute,
			BrowserAbsoluteLimit:  12 * time.Hour,
			MySQLIdleTimeout:      30 * time.Minute,
			MySQLMaxDuration:      8 * time.Hour,
			ShutdownDrainDeadline: 30 * time.Second,
		},
		RateLimits: RateLimits{
			CredentialFailures:             5,
			SourceFailures:                 20,
			FailureWindow:                  10 * time.Minute,
			CredentialIssuanceUserLimit:    10,
			CredentialIssuanceSessionLimit: 5,
			CredentialIssuanceWindow:       10 * time.Minute,
			MaxMySQLSessions:               100,
			MaxQueryBytes:                  64 * 1024,
			MaxResultRows:                  10_000,
			MaxResultBytes:                 64 * 1024 * 1024,
		},
		Setup: Setup{AllowDefaultSetup: true},
		Audit: Audit{FilePath: "audit.jsonl"},
	}
}

// Load reads a TOML configuration file and validates it with defaults applied.
func Load(path string) (Config, error) {
	cfg := Default()
	metadata, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, err
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return Config{}, fmt.Errorf("%w: unknown TOML keys: %s", ErrInvalid, formatUndecoded(undecoded))
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate applies missing defaults and rejects unsafe or incomplete settings.
func (c *Config) Validate() error {
	defaults := Default()
	c.applyDefaults(defaults)

	if c.Environment != EnvironmentDevelopment && c.Environment != EnvironmentProduction {
		return fmt.Errorf("%w: unknown environment %q", ErrInvalid, c.Environment)
	}
	if c.HTTP.ListenAddr == "" || c.MySQL.ListenAddr == "" {
		return fmt.Errorf("%w: listener addresses are required", ErrInvalid)
	}
	if c.Environment == EnvironmentProduction && (!c.HTTP.TLS.Enabled || !c.MySQL.TLS.Enabled) {
		return fmt.Errorf("%w: production requires HTTP and MySQL TLS", ErrInvalid)
	}
	if c.HTTP.TLS.Enabled && (c.HTTP.TLS.CertFile == "" || c.HTTP.TLS.KeyFile == "") {
		return fmt.Errorf("%w: HTTP TLS requires cert_file and key_file", ErrInvalid)
	}
	if c.MySQL.TLS.Enabled && (c.MySQL.TLS.CertFile == "" || c.MySQL.TLS.KeyFile == "") {
		return fmt.Errorf("%w: MySQL TLS requires cert_file and key_file", ErrInvalid)
	}
	if c.Environment == EnvironmentProduction && c.Upstream.TLSSkipVerify {
		return fmt.Errorf("%w: production upstream TLS cannot skip verification", ErrInvalid)
	}
	if c.Environment == EnvironmentProduction &&
		(c.Secrets.UpstreamPasswordEnv == "" && c.Secrets.UpstreamPasswordFile == "") {
		return fmt.Errorf("%w: production upstream password must use env or file secret reference", ErrInvalid)
	}
	if c.Environment == EnvironmentProduction && c.Upstream.Password != "" {
		return fmt.Errorf("%w: production upstream password must not be embedded in TOML", ErrInvalid)
	}
	if c.OTP.UsernameEntropyBits < 96 {
		return fmt.Errorf("%w: OTP username entropy must be at least 96 bits", ErrInvalid)
	}
	if c.OTP.PasswordEntropyBits < 192 {
		return fmt.Errorf("%w: OTP password entropy must be at least 192 bits", ErrInvalid)
	}
	if c.RateLimits.MaxQueryBytes <= 0 || c.RateLimits.MaxResultRows <= 0 ||
		c.RateLimits.MaxResultBytes <= 0 || c.RateLimits.MaxMySQLSessions <= 0 {
		return fmt.Errorf("%w: resource limits must be positive", ErrInvalid)
	}

	return nil
}

func (c *Config) applyDefaults(defaults Config) {
	if c.Environment == "" {
		c.Environment = defaults.Environment
	}
	if c.HTTP.ListenAddr == "" {
		c.HTTP.ListenAddr = defaults.HTTP.ListenAddr
	}
	if c.MySQL.ListenAddr == "" {
		c.MySQL.ListenAddr = defaults.MySQL.ListenAddr
	}
	if c.OTP.TTL <= 0 {
		c.OTP.TTL = defaults.OTP.TTL
	}
	if c.OTP.UsernameEntropyBits <= 0 {
		c.OTP.UsernameEntropyBits = defaults.OTP.UsernameEntropyBits
	}
	if c.OTP.PasswordEntropyBits <= 0 {
		c.OTP.PasswordEntropyBits = defaults.OTP.PasswordEntropyBits
	}
	if c.Sessions.BrowserIdleTimeout <= 0 {
		c.Sessions.BrowserIdleTimeout = defaults.Sessions.BrowserIdleTimeout
	}
	if c.Sessions.BrowserAbsoluteLimit <= 0 {
		c.Sessions.BrowserAbsoluteLimit = defaults.Sessions.BrowserAbsoluteLimit
	}
	if c.Sessions.MySQLIdleTimeout <= 0 {
		c.Sessions.MySQLIdleTimeout = defaults.Sessions.MySQLIdleTimeout
	}
	if c.Sessions.MySQLMaxDuration <= 0 {
		c.Sessions.MySQLMaxDuration = defaults.Sessions.MySQLMaxDuration
	}
	if c.Sessions.ShutdownDrainDeadline <= 0 {
		c.Sessions.ShutdownDrainDeadline = defaults.Sessions.ShutdownDrainDeadline
	}
	if c.RateLimits.CredentialFailures <= 0 {
		c.RateLimits.CredentialFailures = defaults.RateLimits.CredentialFailures
	}
	if c.RateLimits.SourceFailures <= 0 {
		c.RateLimits.SourceFailures = defaults.RateLimits.SourceFailures
	}
	if c.RateLimits.FailureWindow <= 0 {
		c.RateLimits.FailureWindow = defaults.RateLimits.FailureWindow
	}
	if c.RateLimits.CredentialIssuanceUserLimit <= 0 {
		c.RateLimits.CredentialIssuanceUserLimit = defaults.RateLimits.CredentialIssuanceUserLimit
	}
	if c.RateLimits.CredentialIssuanceSessionLimit <= 0 {
		c.RateLimits.CredentialIssuanceSessionLimit = defaults.RateLimits.CredentialIssuanceSessionLimit
	}
	if c.RateLimits.CredentialIssuanceWindow <= 0 {
		c.RateLimits.CredentialIssuanceWindow = defaults.RateLimits.CredentialIssuanceWindow
	}
	if c.RateLimits.MaxMySQLSessions <= 0 {
		c.RateLimits.MaxMySQLSessions = defaults.RateLimits.MaxMySQLSessions
	}
	if c.RateLimits.MaxQueryBytes <= 0 {
		c.RateLimits.MaxQueryBytes = defaults.RateLimits.MaxQueryBytes
	}
	if c.RateLimits.MaxResultRows <= 0 {
		c.RateLimits.MaxResultRows = defaults.RateLimits.MaxResultRows
	}
	if c.RateLimits.MaxResultBytes <= 0 {
		c.RateLimits.MaxResultBytes = defaults.RateLimits.MaxResultBytes
	}
	if c.Audit.FilePath == "" {
		c.Audit.FilePath = defaults.Audit.FilePath
	}
}

func formatUndecoded(keys []toml.Key) string {
	formatted := make([]string, 0, len(keys))
	for _, key := range keys {
		formatted = append(formatted, key.String())
	}

	return strings.Join(formatted, ", ")
}
