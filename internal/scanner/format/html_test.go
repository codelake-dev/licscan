package format

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestHTMLProducesValidHTML5Document(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))

	out := buf.String()
	require.True(t, strings.HasPrefix(out, "<!DOCTYPE html>"), "must start with HTML5 doctype")
	require.Contains(t, out, "<html lang=\"en\">")
	require.Contains(t, out, "</html>")
	require.Contains(t, out, "<title>")
}

func TestHTMLContainsAllDependencies(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))

	out := buf.String()
	require.Contains(t, out, "lib-mit")
	require.Contains(t, out, "lib-gpl")
	require.Contains(t, out, "lib-agpl")
}

func TestHTMLIncludesScanPath(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))
	require.Contains(t, buf.String(), "/some/project")
}

func TestHTMLIncludesAttribution(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))
	require.Contains(t, buf.String(), "codelake Technologies LLC")
	require.Contains(t, buf.String(), "Akyros Labs")
}

func TestHTMLIncludesAllSummaryCards(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))

	out := buf.String()
	require.Contains(t, out, "Permissive")
	require.Contains(t, out, "Weak Copyleft")
	require.Contains(t, out, "Strong Copyleft")
	require.Contains(t, out, "Viral / Problematic")
	require.Contains(t, out, "Unknown")
}

func TestHTMLSortsRowsByRiskDescending(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))

	out := buf.String()
	// In the table, AGPL row must precede GPL row must precede MIT row.
	agplPos := strings.Index(out, "lib-agpl")
	gplPos := strings.Index(out, "lib-gpl")
	mitPos := strings.Index(out, "lib-mit")
	require.True(t, agplPos > 0 && agplPos < gplPos)
	require.True(t, gplPos < mitPos)
}

func TestHTMLAppliesRiskCSSClasses(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))

	out := buf.String()
	require.Contains(t, out, `class="badge permissive"`)
	require.Contains(t, out, `class="badge strong"`)
	require.Contains(t, out, `class="badge viral"`)
}

func TestHTMLEscapesMaliciousPackageNames(t *testing.T) {
	r := scanner.NewResult("/project")
	r.Add(scanner.Dependency{
		Name:     "<script>alert('xss')</script>",
		Version:  "1.0.0",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
	})

	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, r))

	out := buf.String()
	require.NotContains(t, out, "<script>alert('xss')</script>",
		"malicious package name must NOT appear unescaped")
	require.Contains(t, out, "&lt;script&gt;",
		"angle brackets must be HTML-escaped")
}

func TestHTMLHandlesEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, scanner.NewResult("/empty")))

	out := buf.String()
	require.Contains(t, out, "No dependencies found")
	require.Contains(t, out, "/empty")
}

func TestHTMLIncludesGeneratedTimestamp(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))
	// RFC3339 format includes year + Z (UTC).
	require.Contains(t, buf.String(), "Generated:")
	require.Contains(t, buf.String(), "Z</div>", "timestamp must be UTC")
}

func TestHTMLRendersDetectorErrors(t *testing.T) {
	r := scanner.NewResult("/x")
	r.Errors = []string{"gomod: read failed: permission denied"}

	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, r))

	out := buf.String()
	require.Contains(t, out, "Detector errors")
	require.Contains(t, out, "permission denied")
}

func TestHTMLContainsDarkThemeColors(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))

	out := buf.String()
	// Quick sanity that the dark-theme CSS is embedded.
	require.Contains(t, out, "--bg: #0d1117", "dark-theme CSS must be inlined")
	require.Contains(t, out, "--permissive: #3fb950")
	require.Contains(t, out, "--strong: #f85149")
}

func TestHTMLContainsDirectVsTransitiveLabels(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))

	out := buf.String()
	require.Contains(t, out, "direct")
	require.Contains(t, out, "transitive")
}

func TestHTMLIsSelfContainedNoExternalAssets(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, HTML(&buf, sampleResult()))

	out := buf.String()
	require.NotContains(t, out, "<link rel=\"stylesheet\"",
		"must not reference external CSS")
	require.NotContains(t, out, "<script src=",
		"must not load external JS")
}

func TestRiskClassForCoverage(t *testing.T) {
	require.Equal(t, "permissive", riskClassFor(scanner.RiskPermissive))
	require.Equal(t, "weak", riskClassFor(scanner.RiskWeakCopyleft))
	require.Equal(t, "strong", riskClassFor(scanner.RiskStrongCopyleft))
	require.Equal(t, "viral", riskClassFor(scanner.RiskViral))
	require.Equal(t, "unknown", riskClassFor(scanner.RiskUnknown))
	require.Equal(t, "unknown", riskClassFor(scanner.RiskLevel(999)))
}
