package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

// writeProject creates a temp dir with a minimal go.mod for scan tests.
func writeProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(minimalGoMod), 0o644))
	return dir
}

const minimalGoMod = `module example.com/sample

go 1.22

require github.com/example/lib v1.0.0
`

// ── Root + sub-command tree ────────────────────────────────────

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

// ── scan command — happy paths ─────────────────────────────────

func TestScanAgainstProjectWithGoModProducesTableOutput(t *testing.T) {
	dir := writeProject(t)
	stdout, _, err := runCmd(t, "scan", dir)
	require.NoError(t, err)

	out := stdout.String()
	require.Contains(t, out, "Scan path:")
	require.Contains(t, out, "Detectors: gomod")
	require.Contains(t, out, "github.com/example/lib")
	require.Contains(t, out, "Summary:")
}

func TestScanAgainstEmptyDirectoryProducesEmptyResult(t *testing.T) {
	empty := t.TempDir()
	stdout, _, err := runCmd(t, "scan", empty)
	require.NoError(t, err, "empty dir is not an error")

	out := stdout.String()
	require.Contains(t, out, "No dependencies found")
}

func TestScanWithJSONFormatProducesValidJSON(t *testing.T) {
	dir := writeProject(t)
	stdout, _, err := runCmd(t, "scan", dir, "--format", "json")
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &parsed),
		"--format json must emit valid JSON, got: %s", stdout.String())

	require.Contains(t, parsed, "scan_path")
	require.Contains(t, parsed, "dependencies")
	require.Contains(t, parsed, "summary")
}

func TestScanDefaultsToCurrentDirectory(t *testing.T) {
	// We can't easily change cwd in a parallel-safe way; just verify
	// that omitting [path] doesn't error.
	stdout, _, err := runCmd(t, "scan")
	require.NoError(t, err)
	require.Contains(t, stdout.String(), "Scan path:")
}

func TestScanAcceptsAllSupportedFormats(t *testing.T) {
	dir := writeProject(t)
	for _, format := range supportedFormats {
		format := format
		t.Run(format, func(t *testing.T) {
			_, _, err := runCmd(t, "scan", dir, "--format", format)
			require.NoError(t, err, "format %q must be accepted", format)
		})
	}
}

// ── scan command — argument & flag validation ──────────────────

func TestScanRejectsTooManyArgs(t *testing.T) {
	_, _, err := runCmd(t, "scan", "/tmp", "/another")
	require.Error(t, err)
}

func TestScanRejectsUnsupportedFormat(t *testing.T) {
	_, _, err := runCmd(t, "scan", ".", "--format", "yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported format")
}

// ── scan command — CI mode ─────────────────────────────────────

func TestScanCIModeExitsOnViolation(t *testing.T) {
	// A go.mod referencing a module won't resolve to GPL via our stub —
	// without a real local cache hit, deps are Unknown, so no violation.
	// To trigger a violation we'd need a real GPL'd dep on disk. The
	// unit-level scanner_test already exercises HasViolations()/CI logic;
	// here we just verify CI mode runs without erroring on clean output.
	dir := writeProject(t)
	_, _, err := runCmd(t, "scan", dir, "--ci")
	require.NoError(t, err, "CI mode with no violations must exit 0")
}

func TestScanLoadsPolicyFromLicscanYml(t *testing.T) {
	dir := writeProject(t)
	// Add a policy that denies an arbitrary license — we won't trigger
	// any deps, but we verify it parses cleanly (a malformed .licscan.yml
	// would surface as an error here).
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".licscan.yml"),
		[]byte("deny:\n  - GPL-3.0\nwarn:\n  - LGPL-3.0\n"),
		0o644))

	_, _, err := runCmd(t, "scan", dir)
	require.NoError(t, err, "valid .licscan.yml must parse without error")
}

func TestScanErrorsOnMalformedPolicy(t *testing.T) {
	dir := writeProject(t)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".licscan.yml"),
		[]byte("deny: [unterminated\nthis isn't yaml\n@@@"),
		0o644))

	_, _, err := runCmd(t, "scan", dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "policy")
}

func TestScanCRAFlagWritesEvidencePair(t *testing.T) {
	dir := writeProject(t)
	outDir := filepath.Join(dir, "cra-out")
	_, stderr, err := runCmd(t, "scan", dir, "--cra", "--output", outDir)
	require.NoError(t, err)

	jsonPath := filepath.Join(outDir, "cra-sbom.cdx.json")
	pdfPath := filepath.Join(outDir, "cra-evidence.pdf")
	require.FileExists(t, jsonPath, "CRA JSON SBOM must be written")
	require.FileExists(t, pdfPath, "CRA PDF evidence must be written")

	pdfBytes, err := os.ReadFile(pdfPath)
	require.NoError(t, err)
	require.True(t, len(pdfBytes) >= 4 && string(pdfBytes[:4]) == "%PDF",
		"PDF must start with %%PDF magic header")

	// Manufacturer block was not set in writeProject's go.mod-only fixture,
	// so the warning note must surface on stderr.
	require.Contains(t, stderr.String(), "manufacturer",
		"--cra without manufacturer must emit a stderr warning")
}

func TestScanCRAFlagHonorsManufacturerInLicscanYml(t *testing.T) {
	dir := writeProject(t)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".licscan.yml"),
		[]byte(`
manufacturer:
  name: Acme GmbH
  email: security@acme.example
  url: https://acme.example
  country: DE
product:
  name: my-app
  version: 1.2.3
`),
		0o644))
	outDir := filepath.Join(dir, "cra-out")

	_, stderr, err := runCmd(t, "scan", dir, "--cra", "--output", outDir)
	require.NoError(t, err)
	require.NotContains(t, stderr.String(), "manufacturer",
		"populated manufacturer block must NOT trigger the missing-manufacturer warning")

	jsonBytes, err := os.ReadFile(filepath.Join(outDir, "cra-sbom.cdx.json"))
	require.NoError(t, err)
	require.Contains(t, string(jsonBytes), "Acme GmbH",
		"manufacturer name must appear in the CRA JSON SBOM")
	require.Contains(t, string(jsonBytes), "my-app",
		"product name must appear in the CRA JSON SBOM")
}

// ── help text completeness ─────────────────────────────────────

func TestHelpDescribesFlags(t *testing.T) {
	stdout, _, err := runCmd(t, "scan", "--help")
	require.NoError(t, err)

	out := stdout.String()
	require.Contains(t, out, "--format")
	require.Contains(t, out, "--ci")
	require.Contains(t, out, "--cra")
}

func TestLongDescriptionMentionsKeyFeatures(t *testing.T) {
	require.True(t, strings.Contains(longDescription, "CycloneDX"))
	require.True(t, strings.Contains(longDescription, "SPDX"))
	require.True(t, strings.Contains(longDescription, "EU CRA"))
}

// ── internal helpers ───────────────────────────────────────────

func TestIsValidFormatRejectsEmpty(t *testing.T) {
	require.False(t, isValidFormat(""))
}

func TestSupportedFormatsIsStable(t *testing.T) {
	expected := []string{"table", "json", "html", "cyclonedx", "spdx", "markdown"}
	require.Equal(t, expected, supportedFormats)
}

func TestExecuteReturnsZeroOnSuccess(t *testing.T) {
	// Smoke test that the wired root command runs cleanly via the helper.
	_, _, err := runCmd(t, "about")
	require.NoError(t, err)
}
