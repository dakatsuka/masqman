// Package app contains process-level metadata shared by Masqman commands.
package app

// Name is the executable and product name used in user-facing command output.
const Name = "masqman"

// Version is overridden by release builds. Development builds use "dev".
var Version = "dev"

// Banner returns a short identifier for logs and command output.
func Banner() string {
	return Name + " " + Version
}
