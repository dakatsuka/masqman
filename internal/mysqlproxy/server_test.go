package mysqlproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakatsuka/masqman/internal/config"
)

func TestServerServesAcceptedConnection(t *testing.T) {
	t.Parallel()

	protocolServer := &recordingProtocolServer{}
	upstream := &recordingUpstream{}
	mysqlServer := newServer(serverConfig{
		Config:            configWithAllowedAppSchema(),
		Verifier:          &recordingVerifier{},
		ProtocolServer:    protocolServer,
		UpstreamConnector: &recordingUpstreamConnector{upstream: upstream},
	})
	listener := newRecordingListener()
	conn := &recordingConn{remoteAddr: "10.0.0.1:60000"}
	listener.accepts <- acceptResult{conn: conn}
	listener.accepts <- acceptResult{err: net.ErrClosed}

	err := mysqlServer.Serve(listener)
	if err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	if protocolServer.authHandler == nil {
		t.Fatal("accepted connection was not served")
	}
	if !conn.closed {
		t.Fatal("accepted connection was not closed after command loop ended")
	}
}

type acceptResult struct {
	conn net.Conn
	err  error
}

type recordingListener struct {
	accepts chan acceptResult
	closed  bool
}

func newRecordingListener() *recordingListener {
	return &recordingListener{accepts: make(chan acceptResult, 4)}
}

func (listener *recordingListener) Accept() (net.Conn, error) {
	result := <-listener.accepts
	if result.err != nil {
		return nil, result.err
	}

	return result.conn, nil
}

func (listener *recordingListener) Close() error {
	listener.closed = true

	return nil
}

func (listener *recordingListener) Addr() net.Addr {
	return stringAddr("127.0.0.1:3307")
}

var _ net.Listener = (*recordingListener)(nil)

func TestServerReturnsAcceptErrors(t *testing.T) {
	t.Parallel()

	acceptErr := errors.New("accept failed")
	mysqlServer := newServer(serverConfig{
		Config:         config.Default(),
		Verifier:       &recordingVerifier{},
		ProtocolServer: &recordingProtocolServer{},
	})
	listener := newRecordingListener()
	listener.accepts <- acceptResult{err: acceptErr}

	err := mysqlServer.Serve(listener)
	if !errors.Is(err, acceptErr) {
		t.Fatalf("Serve() error = %v, want %v", err, acceptErr)
	}
}

func TestServerListenAndServeUsesConfiguredAddress(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.MySQL.ListenAddr = "127.0.0.1:43307"
	listener := newRecordingListener()
	listener.accepts <- acceptResult{err: net.ErrClosed}
	mysqlServer := newServer(serverConfig{
		Config:         cfg,
		Verifier:       &recordingVerifier{},
		ProtocolServer: &recordingProtocolServer{},
		Listen: func(network string, address string) (net.Listener, error) {
			if network != "tcp" {
				t.Fatalf("network = %q, want tcp", network)
			}
			if address != "127.0.0.1:43307" {
				t.Fatalf("address = %q, want 127.0.0.1:43307", address)
			}

			return listener, nil
		},
	})

	if err := mysqlServer.ListenAndServe(); err != nil {
		t.Fatalf("ListenAndServe() error = %v, want nil", err)
	}
}

func TestNewServerBuildsDefaultProtocolServer(t *testing.T) {
	t.Parallel()

	mysqlServer, err := NewServer(config.Default(), &recordingVerifier{})
	if err != nil {
		t.Fatalf("NewServer() error = %v, want nil", err)
	}
	if mysqlServer.protocolServer == nil {
		t.Fatal("protocolServer = nil, want default go-mysql protocol server")
	}
}

func TestNewServerReturnsMySQLTLSConfigError(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.MySQL.TLS.Enabled = true
	cfg.MySQL.TLS.CertFile = "missing.crt"
	cfg.MySQL.TLS.KeyFile = "missing.key"

	_, err := NewServer(cfg, &recordingVerifier{})
	if err == nil {
		t.Fatal("NewServer() error = nil, want TLS config error")
	}
	if !strings.Contains(err.Error(), "load MySQL TLS certificate") {
		t.Fatalf("NewServer() error = %v, want MySQL TLS certificate error", err)
	}
}

func TestNewServerBuildsConfiguredTLSProtocolServer(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeTestCertificate(t)
	cfg := config.Default()
	cfg.MySQL.TLS.Enabled = true
	cfg.MySQL.TLS.CertFile = certFile
	cfg.MySQL.TLS.KeyFile = keyFile

	mysqlServer, err := NewServer(cfg, &recordingVerifier{})
	if err != nil {
		t.Fatalf("NewServer() error = %v, want nil", err)
	}
	if mysqlServer.protocolServer == nil {
		t.Fatal("protocolServer = nil, want configured TLS protocol server")
	}
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "mysql.crt")
	keyFile := filepath.Join(dir, "mysql.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	return certFile, keyFile
}
