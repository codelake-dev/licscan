package format

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestSARIFProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SARIF(&buf, sampleResultWithVerdicts()))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed), "output must be valid JSON")
}

func TestSARIFSchemaAndVersion(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SARIF(&buf, sampleResultWithVerdicts()))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	assert.Equal(t, "2.1.0", parsed.Version)
	assert.Contains(t, parsed.Schema, "sarif-schema-2.1.0")
	require.Len(t, parsed.Runs, 1)
	assert.Equal(t, "licscan", parsed.Runs[0].Tool.Driver.Name)
	assert.Equal(t, "https://licscan.dev", parsed.Runs[0].Tool.Driver.InformationURI)
}

func TestSARIFOnlyEmitsWarnAndDeny(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SARIF(&buf, sampleResultWithVerdicts()))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	results := parsed.Runs[0].Results
	for _, r := range results {
		assert.NotEqual(t, "note", r.Level, "permissive deps should not appear in SARIF results")
	}
	assert.Len(t, results, 2, "should have one warn + one deny result")
}

func TestSARIFDenyMapsToError(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SARIF(&buf, sampleResultWithVerdicts()))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	for _, r := range parsed.Runs[0].Results {
		if r.Properties.Verdict == "deny" {
			assert.Equal(t, "error", r.Level)
		}
	}
}

func TestSARIFWarnMapsToWarning(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SARIF(&buf, sampleResultWithVerdicts()))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	for _, r := range parsed.Runs[0].Results {
		if r.Properties.Verdict == "warn" {
			assert.Equal(t, "warning", r.Level)
		}
	}
}

func TestSARIFResultLocationsPointToManifest(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SARIF(&buf, sampleResultWithVerdicts()))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	for _, r := range parsed.Runs[0].Results {
		require.Len(t, r.Locations, 1)
		assert.Equal(t, "go.mod", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
}

func TestSARIFRulesAreDeduped(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "a", Version: "1.0", Ecosystem: "gomod", Manifest: "go.mod",
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
		Verdict:  "deny",
	})
	r.Add(scanner.Dependency{
		Name: "b", Version: "2.0", Ecosystem: "gomod", Manifest: "go.mod",
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
		Verdict:  "deny",
	})

	var buf bytes.Buffer
	require.NoError(t, SARIF(&buf, r))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	assert.Len(t, parsed.Runs[0].Tool.Driver.Rules, 1, "same license should produce one rule")
	assert.Len(t, parsed.Runs[0].Results, 2, "each dep should produce its own result")
}

func TestSARIFEmptyResultProducesValidOutput(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SARIF(&buf, scanner.NewResult("/empty")))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	assert.Len(t, parsed.Runs[0].Results, 0)
	assert.Len(t, parsed.Runs[0].Tool.Driver.Rules, 0)
}

func sampleResultWithVerdicts() *scanner.Result {
	r := scanner.NewResult("/some/project")
	r.Detectors = []string{"gomod"}
	r.Add(scanner.Dependency{
		Name: "lib-mit", Version: "v1.0.0", Ecosystem: "gomod", Manifest: "go.mod",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
		Verdict:  "allow",
	})
	r.Add(scanner.Dependency{
		Name: "lib-mpl", Version: "v2.1.0", Ecosystem: "gomod", Manifest: "go.mod",
		Licenses: []scanner.License{scanner.NewLicense("MPL-2.0", "")},
		Verdict:  "warn",
	})
	r.Add(scanner.Dependency{
		Name: "lib-agpl", Version: "v2.0.0", Ecosystem: "gomod", Manifest: "go.mod",
		Licenses: []scanner.License{scanner.NewLicense("AGPL-3.0", "")},
		Verdict:  "deny", Reason: "policy: deny viral",
	})
	return r
}
