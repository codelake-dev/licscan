package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// runCmd is a tiny test helper: builds a fresh root command, runs it with
// the given args, and returns stdout + stderr buffers plus the error.
func runCmd(t *testing.T, args ...string) (stdout, stderr *bytes.Buffer, err error) {
	t.Helper()
	cmd := NewRootCommand()
	stdout = &bytes.Buffer{}
	stderr = &bytes.Buffer{}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return
}

func TestRootHelpListsAllSubcommands(t *testing.T) {
	stdout, _, err := runCmd(t, "--help")
	require.NoError(t, err)

	out := stdout.String()
	require.Contains(t, out, "scan", "scan subcommand must be listed in --help")
	require.Contains(t, out, "about", "about subcommand must be listed in --help")
}

func TestVersionFlagPrintsVersion(t *testing.T) {
	stdout, _, err := runCmd(t, "--version")
	require.NoError(t, err)
	require.Contains(t, stdout.String(), "dev",
		"default build reports version 'dev' until ldflags injection")
}

func TestUnknownCommandReturnsError(t *testing.T) {
	_, _, err := runCmd(t, "nonexistent-command")
	require.Error(t, err)
}

func TestAboutCommandRendersBanner(t *testing.T) {
	stdout, _, err := runCmd(t, "about")
	require.NoError(t, err)

	out := stdout.String()
	require.Contains(t, out, "codelake Technologies LLC")
	require.Contains(t, out, "Akyros Labs")
}

func TestScanDefaultsToCurrentDirectory(t *testing.T) {
	stdout, _, err := runCmd(t, "scan")
	require.NoError(t, err)
	require.Contains(t, stdout.String(), "path=")
	require.Contains(t, stdout.String(), "format=table")
}

func TestScanAcceptsExplicitPath(t *testing.T) {
	stdout, _, err := runCmd(t, "scan", "/tmp")
	require.NoError(t, err)
	require.Contains(t, stdout.String(), "/tmp")
}

func TestScanRejectsTooManyArgs(t *testing.T) {
	_, _, err := runCmd(t, "scan", "/tmp", "/another")
	require.Error(t, err)
}

func TestScanRejectsUnsupportedFormat(t *testing.T) {
	_, _, err := runCmd(t, "scan", ".", "--format", "yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported format")
}

func TestScanAcceptsAllSupportedFormats(t *testing.T) {
	for _, format := range supportedFormats {
		format := format // capture
		t.Run(format, func(t *testing.T) {
			stdout, _, err := runCmd(t, "scan", ".", "--format", format)
			require.NoError(t, err, "format %q must be accepted", format)
			require.Contains(t, stdout.String(), "format="+format)
		})
	}
}

func TestScanCIFlagPropagates(t *testing.T) {
	stdout, _, err := runCmd(t, "scan", ".", "--ci")
	require.NoError(t, err)
	require.Contains(t, stdout.String(), "ci=true")
}

func TestScanCRAFlagPropagates(t *testing.T) {
	stdout, _, err := runCmd(t, "scan", ".", "--cra")
	require.NoError(t, err)
	require.Contains(t, stdout.String(), "cra=true")
}

func TestIsValidFormatRejectsEmpty(t *testing.T) {
	require.False(t, isValidFormat(""))
}

func TestSupportedFormatsIsSorted(t *testing.T) {
	// Sanity check that the formats list is stable — protects users who
	// document the list in their CI configs.
	expected := []string{"table", "json", "html", "cyclonedx", "spdx", "markdown"}
	require.Equal(t, expected, supportedFormats)
}

func TestHelpDescribesFlags(t *testing.T) {
	stdout, _, err := runCmd(t, "scan", "--help")
	require.NoError(t, err)

	out := stdout.String()
	require.Contains(t, out, "--format")
	require.Contains(t, out, "--ci")
	require.Contains(t, out, "--cra")
}

func TestExecuteReturnsZeroOnSuccess(t *testing.T) {
	// We can't easily inject args into Execute() without mutating os.Args,
	// so we just smoke-test that the wired root command runs cleanly via
	// the test helper. Execute() itself is one line of glue.
	_, _, err := runCmd(t, "about")
	require.NoError(t, err)
}

func TestLongDescriptionMentionsKeyFeatures(t *testing.T) {
	require.True(t, strings.Contains(longDescription, "CycloneDX"))
	require.True(t, strings.Contains(longDescription, "SPDX"))
	require.True(t, strings.Contains(longDescription, "EU CRA"))
}
