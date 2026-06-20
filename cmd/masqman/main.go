// Command masqman starts the Masqman MySQL masking proxy.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/dakatsuka/masqman/internal/app"
	"github.com/dakatsuka/masqman/internal/audit"
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

	listener, err := new(net.ListenConfig).Listen(ctx, "tcp", cfg.MySQL.ListenAddr)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
	}()

	err = mysqlServer.ServeContext(ctx, listener)
	if ctx.Err() != nil {
		return nil
	}

	return err
}
