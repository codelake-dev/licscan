package cli

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/codelake-ai/licscan/internal/scanner"
	"github.com/codelake-ai/licscan/internal/scanner/detectors"
	"github.com/codelake-ai/licscan/internal/scanner/format"
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

// defaultDetectors is the canonical detector set the CLI ships with.
// Each new package-manager detector gets added here.
var defaultDetectors = []scanner.Detector{
	&detectors.GoMod{},
	&detectors.Npm{},
}

func runScan(cmd *cobra.Command, path string, opts *scanOptions) error {
	if !isValidFormat(opts.format) {
		return fmt.Errorf("unsupported format %q (allowed: %v)", opts.format, supportedFormats)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path %q: %w", path, err)
	}

	result, err := scanner.New(defaultDetectors...).Scan(absPath)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if err := renderResult(cmd.OutOrStdout(), opts.format, result); err != nil {
		return fmt.Errorf("render %s: %w", opts.format, err)
	}

	// CI mode: exit code 1 if any risk-level above WeakCopyleft is present.
	// Policy-engine-driven exits land with the .licscan.yml feature.
	if opts.ci && result.HasViolations() {
		return fmt.Errorf("policy violation: %d high-risk dependency/ies found",
			result.Summary[scanner.RiskStrongCopyleft.String()]+result.Summary[scanner.RiskViral.String()])
	}

	if opts.cra {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
			"note: EU CRA-compliant SBOM emission lands once the dedicated exporter ships in the next sprint")
	}

	return nil
}

func renderResult(w io.Writer, formatName string, result *scanner.Result) error {
	switch formatName {
	case "table":
		return format.Table(w, result)
	case "json":
		return format.JSON(w, result)
	case "html", "cyclonedx", "spdx", "markdown":
		// Placeholders — exporters land in subsequent sprints.
		return format.JSON(w, result)
	default:
		return fmt.Errorf("unsupported format %q", formatName)
	}
}

func isValidFormat(format string) bool {
	for _, f := range supportedFormats {
		if f == format {
			return true
		}
	}
	return false
}
