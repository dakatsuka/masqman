package mysqlproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	appconfig "github.com/dakatsuka/masqman/internal/config"

	"github.com/go-mysql-org/go-mysql/client"
)

const upstreamConnectTimeout = 10 * time.Second

type upstreamConnector struct {
	config  appconfig.Config
	connect upstreamConnectFunc
}

type upstreamConnectFunc func(context.Context, upstreamConnectionSpec) (upstreamSession, error)

type upstreamConnectionSpec struct {
	Addr      string
	Username  string
	Password  string
	Database  string
	TLSConfig *tls.Config
}

func newUpstreamConnector(config appconfig.Config) *upstreamConnector {
	return &upstreamConnector{
		config:  config,
		connect: connectUpstreamSession,
	}
}

func (connector *upstreamConnector) Connect(ctx context.Context) (upstreamSession, error) {
	password, err := connector.config.UpstreamPassword()
	if err != nil {
		return nil, err
	}

	tlsConfig, _, err := upstreamTLSConfig(connector.config)
	if err != nil {
		return nil, err
	}

	connect := connector.connect
	if connect == nil {
		connect = connectUpstreamSession
	}

	return connect(ctx, upstreamConnectionSpec{
		Addr:      connector.config.Upstream.Addr,
		Username:  connector.config.Upstream.Username,
		Password:  password,
		Database:  connector.config.Upstream.Database,
		TLSConfig: tlsConfig,
	})
}

func connectUpstreamSession(ctx context.Context, spec upstreamConnectionSpec) (upstreamSession, error) {
	options := make([]client.Option, 0, 1)
	if spec.TLSConfig != nil {
		options = append(options, func(conn *client.Conn) error {
			conn.SetTLSConfig(spec.TLSConfig)

			return nil
		})
	}

	return client.ConnectWithContext(
		ctx,
		spec.Addr,
		spec.Username,
		spec.Password,
		spec.Database,
		upstreamConnectTimeout,
		options...,
	)
}

func upstreamTLSConfig(config appconfig.Config) (*tls.Config, bool, error) {
	upstream := config.Upstream
	if !upstream.TLSEnabled {
		return nil, false, nil
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         upstreamTLSServerName(upstream),
		InsecureSkipVerify: upstream.TLSSkipVerify, //nolint:gosec // Production validation forbids this setting.
	}
	if upstream.TLSCAFile == "" {
		return tlsConfig, true, nil
	}

	caPEM, err := os.ReadFile(upstream.TLSCAFile)
	if err != nil {
		return nil, false, fmt.Errorf("%w: read upstream TLS CA file %q: %w", appconfig.ErrInvalid, upstream.TLSCAFile, err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, false, fmt.Errorf("%w: upstream TLS CA file %q contains no certificates", appconfig.ErrInvalid, upstream.TLSCAFile)
	}
	tlsConfig.RootCAs = roots

	return tlsConfig, true, nil
}

func upstreamTLSServerName(upstream appconfig.Upstream) string {
	if upstream.TLSServerName != "" {
		return upstream.TLSServerName
	}

	host, _, err := net.SplitHostPort(upstream.Addr)
	if err != nil {
		return upstream.Addr
	}

	return host
}
