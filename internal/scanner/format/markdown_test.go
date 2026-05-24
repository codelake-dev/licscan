package format

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// ── header + summary ───────────────────────────────────────────

func TestMarkdownIncludesH1Heading(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	require.Contains(t, buf.String(), "# LicScan Report")
}

func TestMarkdownIncludesScanMetadata(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	out := buf.String()
	require.Contains(t, out, "/some/project")
	require.Contains(t, out, "Detectors:")
	require.Contains(t, out, "Total dependencies:")
	require.Contains(t, out, "Generated:")
}

func TestMarkdownIncludesSummaryTable(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	out := buf.String()
	require.Contains(t, out, "## Summary")
	require.Contains(t, out, "| Risk | Count |")
	require.Contains(t, out, "Permissive")
	require.Contains(t, out, "Viral / Problematic")
}

func TestMarkdownSummaryUsesRiskEmojis(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	out := buf.String()
	require.Contains(t, out, "✅")
	require.Contains(t, out, "🔴")
	require.Contains(t, out, "❌")
}

// ── dependency table ───────────────────────────────────────────

func TestMarkdownIncludesAllDependencies(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	out := buf.String()
	require.Contains(t, out, "lib-mit")
	require.Contains(t, out, "lib-gpl")
	require.Contains(t, out, "lib-agpl")
}

func TestMarkdownSortsByDescendingRisk(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	out := buf.String()
	agplPos := strings.Index(out, "lib-agpl")
	gplPos := strings.Index(out, "lib-gpl")
	mitPos := strings.Index(out, "lib-mit")
	require.True(t, agplPos > 0 && agplPos < gplPos)
	require.True(t, gplPos < mitPos)
}

func TestMarkdownDepsWrappedInDetailsWhenOverThreshold(t *testing.T) {
	r := scanner.NewResult("/big")
	for i := 0; i < markdownCollapseThreshold+1; i++ {
		r.Add(scanner.Dependency{
			Name: "pkg", Version: "1.0", Ecosystem: "npm",
			Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
		})
	}
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, r))
	out := buf.String()
	require.Contains(t, out, "<details>")
	require.Contains(t, out, "</details>")
	require.Contains(t, out, "click to expand")
}

func TestMarkdownDepsNotCollapsedAtOrBelowThreshold(t *testing.T) {
	r := scanner.NewResult("/small")
	for i := 0; i < markdownCollapseThreshold; i++ {
		r.Add(scanner.Dependency{
			Name: "pkg", Version: "1.0", Ecosystem: "npm",
			Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
		})
	}
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, r))
	require.NotContains(t, buf.String(), "<details>")
}

func TestMarkdownShowsDirectVsTransitive(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	out := buf.String()
	require.Contains(t, out, "direct")
	require.Contains(t, out, "transitive")
}

// ── empty + edge cases ─────────────────────────────────────────

func TestMarkdownHandlesEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, scanner.NewResult("/empty")))
	out := buf.String()
	require.Contains(t, out, "## Dependencies")
	require.Contains(t, out, "No dependencies found")
}

// ── policy violations section ──────────────────────────────────

func TestMarkdownIncludesPolicyViolationsWhenPresent(t *testing.T) {
	r := scanner.NewResult("/x")
	r.Add(scanner.Dependency{
		Name: "evil-lib", Version: "1.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
		Verdict:  "deny",
		Reason:   "license GPL-3.0 is in the policy deny list",
	})

	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, r))
	out := buf.String()
	require.Contains(t, out, "## Policy violations")
	require.Contains(t, out, "1 dependency/ies denied")
	require.Contains(t, out, "evil-lib")
	require.Contains(t, out, "GPL-3.0")
	require.Contains(t, out, "deny list")
}

func TestMarkdownOmitsPolicyViolationsWhenNoneDenied(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	require.NotContains(t, buf.String(), "## Policy violations")
}

func TestMarkdownShowsVerdictColumnWhenPolicyActive(t *testing.T) {
	r := scanner.NewResult("/x")
	r.Add(scanner.Dependency{
		Name: "ok-lib", Version: "1.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
		Verdict:  "allow",
	})
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, r))
	out := buf.String()
	require.Contains(t, out, "| Verdict |", "Verdict column must be present when any dep carries a verdict")
	require.Contains(t, out, "✓ allow")
}

func TestMarkdownHidesVerdictColumnWhenPolicyInactive(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	// sampleResult deps have no Verdict set
	require.NotContains(t, buf.String(), "| Verdict |")
}

// ── footer ─────────────────────────────────────────────────────

func TestMarkdownIncludesFooterAttribution(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, sampleResult()))
	out := buf.String()
	require.Contains(t, out, "codelake Technologies LLC")
	require.Contains(t, out, "Akyros Labs")
	require.Contains(t, out, "https://github.com/codelake-dev/licscan")
}

// ── helpers ────────────────────────────────────────────────────

func TestEscapeMarkdownCellPreservesPipesAndNewlines(t *testing.T) {
	require.Equal(t, `a \| b`, escapeMarkdownCell("a | b"))
	require.Equal(t, "a b c", escapeMarkdownCell("a\nb\rc"))
	require.Equal(t, "no special", escapeMarkdownCell("no special"))
}

func TestMarkdownVerdictLabel(t *testing.T) {
	require.Equal(t, "✓ allow", markdownVerdictLabel("allow"))
	require.Equal(t, "⚠ warn", markdownVerdictLabel("warn"))
	require.Equal(t, "✗ deny", markdownVerdictLabel("deny"))
	require.Equal(t, "○ exempt", markdownVerdictLabel("exempt"))
	require.Equal(t, "", markdownVerdictLabel(""))
}

// ── reason cells escape table-breaking chars ───────────────────

func TestMarkdownPolicyViolationsReasonIsEscaped(t *testing.T) {
	r := scanner.NewResult("/x")
	r.Add(scanner.Dependency{
		Name: "tricky", Version: "1.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
		Verdict:  "deny",
		Reason:   "broken | reason\nwith newlines",
	})
	var buf bytes.Buffer
	require.NoError(t, Markdown(&buf, r))
	out := buf.String()
	require.Contains(t, out, `broken \| reason with newlines`,
		"pipes must be escaped and newlines collapsed so the table stays valid")
}
