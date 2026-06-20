// Command masqman starts the Masqman MySQL masking proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dakatsuka/masqman/internal/app"
	"github.com/dakatsuka/masqman/internal/audit"
	"github.com/dakatsuka/masqman/internal/auth"
	"github.com/dakatsuka/masqman/internal/authhttp"
	"github.com/dakatsuka/masqman/internal/config"
	"github.com/dakatsuka/masqman/internal/mysqlproxy"
	"github.com/dakatsuka/masqman/internal/otp"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(runWithContext(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

type starter func(context.Context, config.Config) error

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	return runWithContext(context.Background(), args, stdout, stderr)
}

func runWithContext(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	return runWithStarter(ctx, args, stdout, stderr, startMasqman)
}

func runWithStarter(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, start starter) int {
	flags := flag.NewFlagSet(app.Name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print version and exit")
	configPath := flags.String("config", "", "path to TOML configuration file")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintln(stdout, app.Banner())
		return 0
	}

	if *configPath == "" {
		_, _ = fmt.Fprintf(stderr, "%s: missing required -config path\n", app.Name)
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: load config: %v\n", app.Name, err)
		return 2
	}

	if err := start(ctx, cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: startup: %v\n", app.Name, err)

		return 1
	}

	return 0
}

func startMasqman(ctx context.Context, cfg config.Config) (returnErr error) {
	auditLogger, err := audit.NewFileLoggerWithConfig(audit.FileConfig{
		Path:       cfg.Audit.FilePath,
		MaxBytes:   cfg.Audit.MaxBytes,
		MaxBackups: cfg.Audit.MaxBackups,
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := auditLogger.Close(); returnErr == nil && err != nil {
			returnErr = err
		}
	}()

	otpStore := otp.NewStore(cfg.OTPStoreConfig())
	mysqlServer, err := mysqlproxy.NewServer(cfg, otpStore, auditLogger)
	if err != nil {
		return err
	}
	httpHandler, err := newAuthHTTPHandler(cfg, otpStore)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       cfg.Sessions.BrowserIdleTimeout,
	}

	httpListener, err := new(net.ListenConfig).Listen(ctx, "tcp", cfg.HTTP.ListenAddr)
	if err != nil {
		return err
	}
	defer func() {
		_ = httpListener.Close()
	}()

	mysqlListener, err := new(net.ListenConfig).Listen(ctx, "tcp", cfg.MySQL.ListenAddr)
	if err != nil {
		return err
	}
	defer func() {
		_ = mysqlListener.Close()
	}()

	err = serveMasqman(ctx, cfg, httpServer, httpListener, mysqlServer, mysqlListener)
	if ctx.Err() != nil {
		return nil
	}

	return err
}

type mysqlServeContext interface {
	ServeContext(context.Context, net.Listener) error
}

func newAuthHTTPHandler(cfg config.Config, issuer otp.Issuer) (http.Handler, error) {
	mysqlHost, mysqlPort := mysqlCommandEndpoint(cfg.MySQL.ListenAddr)
	sessions := authhttp.NewSessionStore(authhttp.SessionConfig{
		IdleLifetime:     cfg.Sessions.BrowserIdleTimeout,
		AbsoluteLifetime: cfg.Sessions.BrowserAbsoluteLimit,
	})

	return authhttp.NewHandler(authhttp.HandlerConfig{
		AuthProvider: auth.NewLocalProvider(cfg.Auth.LocalUsers),
		Sessions:     sessions,
		Issuer:       issuer,
		CookieSecure: cfg.Environment == config.EnvironmentProduction || cfg.HTTP.TLS.Enabled,
		MySQLHost:    mysqlHost,
		MySQLPort:    mysqlPort,
	})
}

func serveMasqman(
	ctx context.Context,
	cfg config.Config,
	httpServer *http.Server,
	httpListener net.Listener,
	mysqlServer mysqlServeContext,
	mysqlListener net.Listener,
) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error, 2)
	go func() {
		errs <- serveHTTPContext(
			serveCtx,
			httpServer,
			httpListener,
			cfg.HTTP.TLS,
			cfg.Sessions.ShutdownDrainDeadline,
		)
	}()
	go func() {
		errs <- mysqlServer.ServeContext(serveCtx, mysqlListener)
	}()

	firstErr := <-errs
	cancel()
	secondErr := <-errs
	if ctx.Err() != nil {
		return nil
	}
	if firstErr != nil {
		return firstErr
	}

	return secondErr
}

func serveHTTPContext(
	ctx context.Context,
	server *http.Server,
	listener net.Listener,
	tlsConfig config.TLS,
	shutdownDeadline time.Duration,
) error {
	errs := make(chan error, 1)
	go func() {
		var err error
		if tlsConfig.Enabled {
			err = server.ServeTLS(listener, tlsConfig.CertFile, tlsConfig.KeyFile)
		} else {
			err = server.Serve(listener)
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errs <- err
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownDeadline)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()

			return err
		}

		return <-errs
	}
}

func mysqlCommandEndpoint(listenAddr string) (string, string) {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return listenAddr, ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = ""
	}

	return host, port
}
