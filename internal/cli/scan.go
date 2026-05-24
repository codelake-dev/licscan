package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

// supportedFormats is the closed set of --format values. Kept here so the
// list lives next to the flag declaration and tests can import it.
var supportedFormats = []string{"table", "json", "html", "cyclonedx", "spdx", "markdown"}

type scanOptions struct {
	format string
	ci     bool
	cra    bool
}

func newScanCommand() *cobra.Command {
	opts := &scanOptions{format: "table"}

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a project directory for dependency licenses",
		Long: `Scan walks the given directory (default: current directory), detects every
package manager in use, resolves each dependency's license via SPDX, and
classifies the result by risk category.

Output formats:
  table       Human-readable terminal output (default)
  json        Machine-readable, suitable for CI/CD
  html        Stand-alone HTML report
  cyclonedx   CycloneDX 1.5 SBOM
  spdx        SPDX 2.3 SBOM
  markdown    Markdown summary for READMEs / PR comments`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return runScan(cmd, path, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.format, "format", "f", "table",
		fmt.Sprintf("output format (%v)", supportedFormats))
	cmd.Flags().BoolVar(&opts.ci, "ci",
		false, "CI mode — exit 1 on policy violation")
	cmd.Flags().BoolVar(&opts.cra,
		"cra", false, "emit EU CRA-compliant SBOM (PDF + JSON)")

	return cmd
}

func runScan(cmd *cobra.Command, path string, opts *scanOptions) error {
	if !isValidFormat(opts.format) {
		return fmt.Errorf("unsupported format %q (allowed: %v)", opts.format, supportedFormats)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path %q: %w", path, err)
	}

	// Scanner implementation lands in the next sprint. For now we surface
	// the resolved configuration so users can confirm flag parsing works
	// and integration scripts have a stable contract to test against.
	return writeln(cmd.OutOrStdout(),
		"licscan scan placeholder — path=%s format=%s ci=%t cra=%t",
		absPath, opts.format, opts.ci, opts.cra)
}

func isValidFormat(format string) bool {
	for _, f := range supportedFormats {
		if f == format {
			return true
		}
	}
	return false
}
