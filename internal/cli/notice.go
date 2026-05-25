package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/scanner/format"
	"github.com/codelake-dev/licscan/internal/scanner/policy"
)

type noticeOptions struct {
	output      string
	projectName string
}

func newNoticeCommand() *cobra.Command {
	opts := &noticeOptions{}

	cmd := &cobra.Command{
		Use:   "notice [path]",
		Short: "Generate a THIRD_PARTY_LICENSES / NOTICE file",
		Long: `Scans the project directory and generates a THIRD_PARTY_LICENSES file
listing every dependency with its license. Many open-source licenses
(Apache-2.0, BSD, MIT) require you to include attribution notices when
redistributing. This command automates that.

By default, writes to stdout. Use --output to write to a file.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return runNotice(cmd, path, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.output, "output", "o", "",
		"output file path (default: stdout)")
	cmd.Flags().StringVar(&opts.projectName, "project-name", "",
		"project name for the header (auto-detected from .licscan.yml product.name if not set)")

	return cmd
}

func runNotice(cmd *cobra.Command, path string, opts *noticeOptions) error {
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

	projectName := opts.projectName
	if projectName == "" && !pol.Product.IsZero() {
		projectName = pol.Product.Name
	}

	w := cmd.OutOrStdout()
	if opts.output != "" {
		f, err := os.Create(opts.output)
		if err != nil {
			return fmt.Errorf("create %s: %w", opts.output, err)
		}
		defer f.Close()
		w = f
		defer func() {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "NOTICE file written to %s\n", opts.output)
		}()
	}

	return format.Notice(w, result, projectName)
}
