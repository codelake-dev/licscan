package cli

import (
	"github.com/spf13/cobra"

	"github.com/codelake-dev/licscan/internal/lsp"
)

func newLSPCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "lsp",
		Short: "Start the Language Server Protocol server",
		Long: `Starts a JSON-RPC 2.0 LSP server on stdin/stdout for editor integration.

Supported by VS Code, JetBrains (via LSP plugin), Neovim (via lspconfig),
and any editor that speaks LSP.

The server watches manifest files (go.mod, package.json, Cargo.toml, etc.),
scans for license risk on open/save, and publishes diagnostics + inlay hints
showing the license for each dependency inline in the editor.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return lsp.Run(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}
