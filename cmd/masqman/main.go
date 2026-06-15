// Command masqman starts the Masqman MySQL masking proxy.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dakatsuka/masqman/internal/app"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", "", "path to TOML configuration file")
	flag.Parse()

	if *showVersion {
		_, _ = fmt.Fprintln(os.Stdout, app.Banner())
		return
	}

	if *configPath == "" {
		_, _ = fmt.Fprintf(os.Stderr, "%s: configuration is not implemented yet; pass -version to verify the development scaffold\n", app.Name)
		os.Exit(2)
	}

	_, _ = fmt.Fprintf(os.Stderr, "%s: configuration loading is not implemented yet: %s\n", app.Name, *configPath)
	os.Exit(2)
}
