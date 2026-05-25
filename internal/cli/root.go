// Package cli wires the Cobra command tree for the licscan binary.
package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/codelake-dev/licscan/internal/banner"
	"github.com/codelake-dev/licscan/internal/version"
)

// Execute runs the root command. Returns the exit code so callers (main and
// integration tests) can react without calling os.Exit themselves.
func Execute() int {
	cmd := NewRootCommand()
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)
	if err := cmd.Execute(); err != nil {
		// Cobra has already printed the error via SetErr.
		return 1
	}
	return 0
}

// NewRootCommand builds a fresh command tree. Exported so tests can exercise
// it with isolated input/output buffers instead of stdout/stderr.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "licscan",
		Short:         "Open-source license & compliance scanner",
		Long:          banner.Logo + "\n  " + banner.Attribution + "\n\n" + longDescription,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Full(),
	}

	root.SetVersionTemplate(banner.Logo + "\n  " + banner.Attribution + "\n\n" + "{{.Version}}\n")

	root.AddCommand(
		newScanCommand(),
		newAboutCommand(),
	)

	return root
}

const longDescription = `licscan scans a project for the licenses of its dependencies, classifies
them by risk, checks compatibility, and exports SBOMs (CycloneDX / SPDX).

Supports Composer, npm, pip, Go modules, Gemfile, Cargo and Maven.
Includes an EU CRA Compliance mode for regulated software.`
