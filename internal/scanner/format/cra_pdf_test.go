package format

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestCRAPDFProducesValidPDFMagic(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAPDF(&buf, sampleResult(), sampleManifest()))

	out := buf.Bytes()
	require.True(t, len(out) >= 4, "PDF output must be non-trivial")
	require.Equal(t, "%PDF", string(out[:4]), "must start with the PDF magic header")
	// Every well-formed PDF ends with %%EOF (optionally followed by whitespace).
	require.Contains(t, string(out), "%%EOF", "must contain end-of-file marker")
}

func TestCRAPDFMetadataIdentifiesAsCRAEvidence(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAPDF(&buf, sampleResult(), sampleManifest()))
	out := buf.String()

	// PDF body streams are flate-compressed; only the metadata
	// dictionary (Title / Subject / Author / Creator) is searchable.
	// fpdf writes those strings as UTF-16BE, so each ASCII char is
	// preceded by a NUL byte.
	require.Contains(t, out, "\x00E\x00U\x00 \x00C\x00R\x00A",
		"title metadata must include the regulation name")
	require.Contains(t, out, "\x00A\x00r\x00t\x00i\x00c\x00l\x00e\x00 \x001\x003",
		"subject metadata must reference Art. 13")
	require.Contains(t, out, "\x00l\x00i\x00c\x00s\x00c\x00a\x00n",
		"author metadata must identify the tool")
}

func TestCRAPDFTitleMetadataIncludesProductName(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAPDF(&buf, sampleResult(), sampleManifest()))
	out := buf.String()
	// fpdf writes Title as UTF-16BE so 'my-app' shows up with null-byte
	// separators between each ASCII character.
	require.Contains(t, out, "\x00m\x00y\x00-\x00a\x00p\x00p",
		"product name must appear in PDF metadata title (UTF-16BE encoded)")
}

func TestCRAPDFManufacturerEmptyDoesNotPanic(t *testing.T) {
	// Verifies the gray-note path renders without error; substring-
	// matching the body text is not possible due to flate compression.
	var buf bytes.Buffer
	require.NoError(t, CRAPDF(&buf, sampleResult(), CRAManifest{}))
	require.True(t, bytes.HasPrefix(buf.Bytes(), []byte("%PDF")))
}

func TestCRAPDFGrowsWithMoreDependencies(t *testing.T) {
	// Structural sanity: a richer result must produce a larger PDF
	// than an empty one (the dependency table page expands).
	var small, big bytes.Buffer
	require.NoError(t, CRAPDF(&small, scanner.NewResult("/empty"), CRAManifest{}))
	require.NoError(t, CRAPDF(&big, sampleResult(), sampleManifest()))
	require.Greater(t, big.Len(), small.Len(),
		"non-empty result must produce a larger PDF than empty (%d vs %d bytes)",
		big.Len(), small.Len())
}

func TestCRAPDFRendersWhenResultIsEmpty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAPDF(&buf, scanner.NewResult("/empty"), CRAManifest{}))
	require.True(t, bytes.HasPrefix(buf.Bytes(), []byte("%PDF")))
}

func TestCRAPDFTitleFallsBackWhenNoProductName(t *testing.T) {
	require.Equal(t, "EU CRA Evidence", craReportTitle(CRAManifest{}))
}

func TestCRAPDFTitleIncludesProductName(t *testing.T) {
	require.Equal(t, "EU CRA Evidence — my-app", craReportTitle(sampleManifest()))
}

// ── helpers ────────────────────────────────────────────────────

func TestRiskShortCoversAllLevels(t *testing.T) {
	require.Equal(t, "Viral", riskShort(scanner.RiskViral))
	require.Equal(t, "Strong", riskShort(scanner.RiskStrongCopyleft))
	require.Equal(t, "Weak", riskShort(scanner.RiskWeakCopyleft))
	require.Equal(t, "Permissive", riskShort(scanner.RiskPermissive))
	require.Equal(t, "Unknown", riskShort(scanner.RiskUnknown))
	require.Equal(t, "Unknown", riskShort(scanner.RiskLevel(999)))
}

func TestRiskRGBProducesDistinctColorsPerLevel(t *testing.T) {
	seen := map[[3]int]bool{}
	levels := []scanner.RiskLevel{
		scanner.RiskPermissive, scanner.RiskWeakCopyleft,
		scanner.RiskStrongCopyleft, scanner.RiskViral, scanner.RiskUnknown,
	}
	for _, l := range levels {
		r, g, b := riskRGB(l)
		key := [3]int{r, g, b}
		require.False(t, seen[key], "duplicate color for risk level %v", l)
		seen[key] = true
	}
}

func TestTruncate(t *testing.T) {
	require.Equal(t, "hello", truncate("hello", 10))
	require.Equal(t, "hello", truncate("hello", 5))
	require.Equal(t, "hell…", truncate("hello world", 5))
}

func TestJoinStrings(t *testing.T) {
	require.Equal(t, "", joinStrings(nil, ","))
	require.Equal(t, "a", joinStrings([]string{"a"}, ","))
	require.Equal(t, "a, b, c", joinStrings([]string{"a", "b", "c"}, ", "))
}
