// Package banner provides the ASCII logo and branding text rendered in
// `licscan about` and on the `--help` output.
package banner

import (
	"fmt"
	"io"

	"github.com/codelake-dev/licscan/internal/version"
)

// Logo is the LicScan ASCII logo. Kept as a const so it never drifts
// between subcommands.
const Logo = `
 ████   ███
 ░░███  ░░░
  ░███  ████   ██████   █████   ██████   ██████   ████████
  ░███ ░░███  ███░░███ ███░░   ███░░███ ░░░░░███ ░░███░░███
  ░███  ░███ ░███ ░░░ ░░█████ ░███ ░░░   ███████  ░███ ░███
  ░███  ░███ ░███  ███ ░░░░███░███  ███ ███░░███  ░███ ░███
  █████ █████░░██████  ██████ ░░██████ ░░████████ ████ █████
 ░░░░░ ░░░░░  ░░░░░░  ░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░`

// Tagline is the one-line product description shown under the logo.
const Tagline = "Open-source license & compliance scanner for modern codebases."

// Attribution is the legally-required brand line. Always rendered alongside
// the logo so attribution travels with every artefact.
const Attribution = "by codelake Technologies LLC. An Akyros Labs brand."

// Render writes the logo + attribution + version to the given writer.
// Used by `licscan about` and on first-run / --help output.
func Render(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s\n  %s\n\n  %s\n  %s\n", Logo, Attribution, Tagline, version.Short())
	return err
}

// Short writes a compact one-line banner for --help and --version.
func Short(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s\n  %s · %s\n\n", Logo, Attribution, version.Short())
	return err
}
