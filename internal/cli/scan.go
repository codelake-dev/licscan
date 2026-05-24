package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/scanner/detectors"
	"github.com/codelake-dev/licscan/internal/scanner/format"
	"github.com/codelake-dev/licscan/internal/scanner/policy"
)

// supportedFormats is the closed set of --format values. Kept here so the
// list lives next to the flag declaration and tests can import it.
var supportedFormats = []string{"table", "json", "html", "cyclonedx", "spdx", "markdown"}

type scanOptions struct {
	format string
	ci     bool
	cra    bool
	output string
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
		"cra", false, "emit EU CRA-compliant SBOM (PDF + JSON) into --output")
	cmd.Flags().StringVar(&opts.output, "output",
		"./licscan-cra-evidence", "output directory for --cra artefacts")

	return cmd
}

// defaultDetectors is the canonical detector set the CLI ships with.
// Each new package-manager detector gets added here.
var defaultDetectors = []scanner.Detector{
	&detectors.GoMod{},
	&detectors.Npm{},
	&detectors.Composer{},
	&detectors.Cargo{},
	&detectors.Gem{},
	&detectors.Pip{},
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

	pol, err := policy.Load(absPath)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	pol.Apply(result)

	if err := renderResult(cmd.OutOrStdout(), opts.format, result); err != nil {
		return fmt.Errorf("render %s: %w", opts.format, err)
	}

	// CI mode: exit non-zero only when policy explicitly denies something.
	// Exemptions in .licscan.yml allow teams to whitelist specific packages
	// without weakening the global rules.
	if opts.ci && policy.HasDenials(result) {
		printPolicyViolations(cmd.ErrOrStderr(), result)
		denyCount := policy.CountByVerdict(result)[policy.VerdictDeny]
		return fmt.Errorf("policy violation: %d dependency/ies denied", denyCount)
	}

	if opts.cra {
		if err := emitCRAEvidence(cmd, result, pol, opts.output); err != nil {
			return fmt.Errorf("cra: %w", err)
		}
	}

	return nil
}

// emitCRAEvidence writes the EU CRA Article 13 evidence pair
// (CycloneDX JSON + PDF) into the requested output directory and
// emits a stderr summary so the user knows where to find them.
func emitCRAEvidence(cmd *cobra.Command, result *scanner.Result, pol *policy.Policy, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir %q: %w", outputDir, err)
	}

	manifest := format.CRAManifest{
		Manufacturer: pol.Manufacturer,
		Product:      pol.Product,
	}

	if manifest.Manufacturer.IsZero() {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
			"warning: --cra invoked without a manufacturer block in .licscan.yml — "+
				"the evidence is generated but regulator submission requires manufacturer Name/Email/URL/Country (CRA Art. 13(2)).")
	}

	jsonPath := filepath.Join(outputDir, "cra-sbom.cdx.json")
	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", jsonPath, err)
	}
	if err := format.CRAJSON(jsonFile, result, manifest); err != nil {
		_ = jsonFile.Close()
		return fmt.Errorf("write %s: %w", jsonPath, err)
	}
	if err := jsonFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", jsonPath, err)
	}

	pdfPath := filepath.Join(outputDir, "cra-evidence.pdf")
	pdfFile, err := os.Create(pdfPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", pdfPath, err)
	}
	if err := format.CRAPDF(pdfFile, result, manifest); err != nil {
		_ = pdfFile.Close()
		return fmt.Errorf("write %s: %w", pdfPath, err)
	}
	if err := pdfFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", pdfPath, err)
	}

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"\nEU CRA evidence written:\n  %s\n  %s\n", jsonPath, pdfPath)
	return nil
}

func renderResult(w io.Writer, formatName string, result *scanner.Result) error {
	switch formatName {
	case "table":
		return format.Table(w, result)
	case "json":
		return format.JSON(w, result)
	case "html":
		return format.HTML(w, result)
	case "cyclonedx":
		return format.CycloneDX(w, result)
	case "spdx":
		return format.SPDX(w, result)
	case "markdown":
		return format.Markdown(w, result)
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

// printPolicyViolations writes each denied dependency to stderr with its
// reason, so CI logs surface a useful failure explanation alongside the
// non-zero exit code.
func printPolicyViolations(w io.Writer, result *scanner.Result) {
	_, _ = fmt.Fprintln(w, "\nPolicy violations:")
	for _, dep := range result.Dependencies {
		if dep.Verdict != policy.VerdictDeny {
			continue
		}
		_, _ = fmt.Fprintf(w, "  ❌ %s@%s  %s — %s\n",
			dep.Name, dep.Version, dep.PrimaryLicense(), dep.Reason)
	}
}
