package format

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestJSONProducesValidParseableOutput(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JSON(&buf, sampleResult()))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed), "output must be valid JSON")
}

func TestJSONContainsExpectedTopLevelKeys(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JSON(&buf, sampleResult()))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	require.Contains(t, parsed, "scan_path")
	require.Contains(t, parsed, "dependencies")
	require.Contains(t, parsed, "summary")
	require.Contains(t, parsed, "detectors_run")
}

func TestJSONDependenciesHaveStableSchema(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JSON(&buf, sampleResult()))

	var parsed struct {
		Dependencies []struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Ecosystem string `json:"ecosystem"`
			Manifest  string `json:"manifest"`
			Direct    bool   `json:"direct"`
			Licenses  []struct {
				SPDX string `json:"spdx"`
				Risk string `json:"risk"`
			} `json:"licenses"`
		} `json:"dependencies"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	require.Len(t, parsed.Dependencies, 3)

	for _, d := range parsed.Dependencies {
		require.NotEmpty(t, d.Name)
		require.NotEmpty(t, d.Ecosystem)
		require.NotEmpty(t, d.Licenses)
		require.NotEmpty(t, d.Licenses[0].SPDX)
		require.NotEmpty(t, d.Licenses[0].Risk)
	}
}

func TestJSONIsPrettyPrinted(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JSON(&buf, sampleResult()))
	require.Contains(t, buf.String(), "\n  ", "pretty-printed output must contain indented lines")
}

func TestJSONHandlesEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JSON(&buf, scanner.NewResult("/empty")))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	require.Equal(t, "/empty", parsed["scan_path"])
}
