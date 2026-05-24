package cli

import (
	"github.com/spf13/cobra"

	"github.com/codelake-dev/licscan/internal/banner"
)

func newAboutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "about",
		Short: "Print the licscan banner, version, and attribution",
		RunE: func(cmd *cobra.Command, args []string) error {
			return banner.Render(cmd.OutOrStdout())
		},
	}
}
