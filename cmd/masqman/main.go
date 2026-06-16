// Command masqman starts the Masqman MySQL masking proxy.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/dakatsuka/masqman/internal/app"
	"github.com/dakatsuka/masqman/internal/config"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
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

	_, _ = fmt.Fprintf(stderr, "%s: startup is not implemented yet for %s\n", app.Name, cfg.MySQL.ListenAddr)
	return 2
}
