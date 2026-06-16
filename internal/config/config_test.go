package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/config"
)

func TestValidateAppliesDefaultsAndRequiresProductionTLS(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Environment = config.EnvironmentProduction
	cfg.HTTP.TLS.Enabled = false
	cfg.MySQL.TLS.Enabled = true

	err := cfg.Validate()
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("Validate error = %v, want %v", err, config.ErrInvalid)
	}

	cfg.HTTP.TLS.Enabled = true
	cfg.HTTP.TLS.CertFile = "http.crt"
	cfg.HTTP.TLS.KeyFile = "http.key"
	cfg.MySQL.TLS.CertFile = "mysql.crt"
	cfg.MySQL.TLS.KeyFile = "mysql.key"
	cfg.Secrets.UpstreamPasswordEnv = "MASQMAN_UPSTREAM_PASSWORD"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if cfg.OTP.TTL != 10*time.Minute || cfg.Sessions.MySQLIdleTimeout != 30*time.Minute {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
	if cfg.Audit.FilePath == "" {
		t.Fatal("default audit file path is empty")
	}
}

func TestValidateRequiresProductionTLSFiles(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Environment = config.EnvironmentProduction
	cfg.HTTP.TLS.Enabled = true
	cfg.MySQL.TLS.Enabled = true

	err := cfg.Validate()
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("Validate error = %v, want %v", err, config.ErrInvalid)
	}
}

func TestValidateRequiresProductionUpstreamSecretReference(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Environment = config.EnvironmentProduction
	cfg.HTTP.TLS = config.TLS{Enabled: true, CertFile: "http.crt", KeyFile: "http.key"}
	cfg.MySQL.TLS = config.TLS{Enabled: true, CertFile: "mysql.crt", KeyFile: "mysql.key"}
	cfg.Upstream.Password = "plaintext"

	err := cfg.Validate()
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("Validate error = %v, want %v", err, config.ErrInvalid)
	}
}

func TestValidateRejectsWeakOTPLimits(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.OTP.UsernameEntropyBits = 95

	err := cfg.Validate()
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("Validate error = %v, want %v", err, config.ErrInvalid)
	}
}

func TestValidateAppliesAuditDefaultPath(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if cfg.Audit.FilePath == "" {
		t.Fatal("Validate left audit file path empty")
	}
}

func TestLoadReadsTOML(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "masqman.toml")
	input := []byte(`
environment = "development"

[http]
listen_addr = "127.0.0.1:8080"

[mysql]
listen_addr = "127.0.0.1:3307"

[upstream]
addr = "127.0.0.1:33060"
database = "app"
username = "masqman_proxy"
password = "masqman_proxy_password"
tls_enabled = true
tls_ca_file = "/etc/ssl/mysql-ca.pem"

[setup]
allow_schema_selection = ["app"]
allow_default_setup = true

[[auth.local_users]]
username = "alice"
password = "secret"

[secrets]
upstream_password_env = "MASQMAN_UPSTREAM_PASSWORD"

[audit]
file_path = "/var/log/masqman/audit.jsonl"
max_bytes = 1048576
max_backups = 3

[[masking.allow_tables]]
schema = "app"
table = "departments"

[[masking.allow_columns]]
schema = "app"
table = "employees"
columns = ["id", "department_id"]

[masking.allow_column_names]
names = ["created_at"]
`)
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Upstream.Database != "app" ||
		cfg.Upstream.TLSCAFile != "/etc/ssl/mysql-ca.pem" ||
		cfg.Secrets.UpstreamPasswordEnv != "MASQMAN_UPSTREAM_PASSWORD" ||
		len(cfg.Setup.AllowSchemaSelection) != 1 ||
		len(cfg.Masking.AllowTables) != 1 ||
		len(cfg.Masking.AllowColumns) != 1 ||
		len(cfg.Masking.AllowColumnNames.Names) != 1 ||
		cfg.Audit.MaxBytes != 1048576 ||
		cfg.Audit.MaxBackups != 3 ||
		len(cfg.Auth.LocalUsers) != 1 {
		t.Fatalf("Load returned %#v", cfg)
	}
}

func TestLoadRejectsUnknownTOMLKeys(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "masqman.toml")
	if err := os.WriteFile(path, []byte("unknown = true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := config.Load(path)
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("Load error = %v, want %v", err, config.ErrInvalid)
	}
}
