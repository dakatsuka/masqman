package mysqlproxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/config"
)

func TestUpstreamConnectorBuildsConnectionSpec(t *testing.T) {
	t.Setenv("MASQMAN_TEST_UPSTREAM_PASSWORD", "from-env")

	cfg := config.Default()
	cfg.Upstream.Addr = "db.example.test:3306"
	cfg.Upstream.Database = "app"
	cfg.Upstream.Username = "masqman_proxy"
	cfg.Upstream.Password = "inline"
	cfg.Secrets.UpstreamPasswordEnv = "MASQMAN_TEST_UPSTREAM_PASSWORD"

	var captured upstreamConnectionSpec
	expectedSession := &recordingUpstream{}
	connector := newUpstreamConnector(cfg)
	connector.connect = func(_ context.Context, spec upstreamConnectionSpec) (upstreamSession, error) {
		captured = spec

		return expectedSession, nil
	}

	session, err := connector.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect() error = %v, want nil", err)
	}
	if session != expectedSession {
		t.Fatal("Connect() did not return upstream session")
	}
	if captured.Addr != "db.example.test:3306" ||
		captured.Username != "masqman_proxy" ||
		captured.Password != "from-env" ||
		captured.Database != "app" {
		t.Fatalf("connection spec = %#v, want configured upstream fields", captured)
	}
	if captured.TLSConfig != nil {
		t.Fatalf("TLSConfig = %#v, want nil when upstream TLS is disabled", captured.TLSConfig)
	}
}

func TestUpstreamConnectorBuildsTLSConfig(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, testCertificatePEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Upstream.Addr = "db.internal:3306"
	cfg.Upstream.TLSEnabled = true
	cfg.Upstream.TLSCAFile = caPath
	cfg.Upstream.TLSServerName = "mysql.internal"

	var captured upstreamConnectionSpec
	connector := newUpstreamConnector(cfg)
	connector.connect = func(_ context.Context, spec upstreamConnectionSpec) (upstreamSession, error) {
		captured = spec

		return &recordingUpstream{}, nil
	}

	if _, err := connector.Connect(context.Background()); err != nil {
		t.Fatalf("Connect() error = %v, want nil", err)
	}
	if captured.TLSConfig == nil {
		t.Fatal("TLSConfig = nil, want configured TLS")
	}
	if captured.TLSConfig.ServerName != "mysql.internal" {
		t.Fatalf("TLSConfig.ServerName = %q, want mysql.internal", captured.TLSConfig.ServerName)
	}
	if captured.TLSConfig.InsecureSkipVerify {
		t.Fatal("TLSConfig.InsecureSkipVerify = true, want false")
	}
	if captured.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLSConfig.MinVersion = %d, want %d", captured.TLSConfig.MinVersion, tls.VersionTLS12)
	}
	if captured.TLSConfig.RootCAs == nil {
		t.Fatal("TLSConfig.RootCAs = nil, want CA pool from tls_ca_file")
	}
}

func TestUpstreamConnectorDerivesTLSServerNameFromAddress(t *testing.T) {
	cfg := config.Default()
	cfg.Upstream.Addr = "db.internal:3306"
	cfg.Upstream.TLSEnabled = true

	var captured upstreamConnectionSpec
	connector := newUpstreamConnector(cfg)
	connector.connect = func(_ context.Context, spec upstreamConnectionSpec) (upstreamSession, error) {
		captured = spec

		return &recordingUpstream{}, nil
	}

	if _, err := connector.Connect(context.Background()); err != nil {
		t.Fatalf("Connect() error = %v, want nil", err)
	}
	if captured.TLSConfig == nil {
		t.Fatal("TLSConfig = nil, want configured TLS")
	}
	if captured.TLSConfig.ServerName != "db.internal" {
		t.Fatalf("TLSConfig.ServerName = %q, want db.internal", captured.TLSConfig.ServerName)
	}
}

func TestUpstreamConnectorPropagatesConfigurationErrors(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		t.Setenv("MASQMAN_TEST_EMPTY_PASSWORD", "")

		cfg := config.Default()
		cfg.Secrets.UpstreamPasswordEnv = "MASQMAN_TEST_EMPTY_PASSWORD"
		connector := newUpstreamConnector(cfg)
		connector.connect = func(context.Context, upstreamConnectionSpec) (upstreamSession, error) {
			t.Fatal("connect called after password resolution failed")
			return &recordingUpstream{}, nil
		}

		_, err := connector.Connect(context.Background())
		if !errors.Is(err, config.ErrInvalid) {
			t.Fatalf("Connect() error = %v, want %v", err, config.ErrInvalid)
		}
	})

	t.Run("tls ca", func(t *testing.T) {
		cfg := config.Default()
		cfg.Upstream.TLSEnabled = true
		cfg.Upstream.TLSCAFile = filepath.Join(t.TempDir(), "missing-ca.pem")
		connector := newUpstreamConnector(cfg)
		connector.connect = func(context.Context, upstreamConnectionSpec) (upstreamSession, error) {
			t.Fatal("connect called after TLS config failed")
			return &recordingUpstream{}, nil
		}

		_, err := connector.Connect(context.Background())
		if !errors.Is(err, config.ErrInvalid) {
			t.Fatalf("Connect() error = %v, want %v", err, config.ErrInvalid)
		}
	})
}

func TestUpstreamConnectorPropagatesConnectError(t *testing.T) {
	connectErr := errors.New("dial failed")

	cfg := config.Default()
	connector := newUpstreamConnector(cfg)
	connector.connect = func(context.Context, upstreamConnectionSpec) (upstreamSession, error) {
		return nil, connectErr
	}

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, connectErr) {
		t.Fatalf("Connect() error = %v, want %v", err, connectErr)
	}
}

func testCertificatePEM(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}
