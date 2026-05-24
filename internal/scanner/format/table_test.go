package format

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-ai/licscan/internal/scanner"
)

func sampleResult() *scanner.Result {
	r := scanner.NewResult("/some/project")
	r.Detectors = []string{"gomod"}
	r.Add(scanner.Dependency{
		Name: "lib-mit", Version: "v1.0.0", Ecosystem: "gomod", Direct: true,
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
	})
	r.Add(scanner.Dependency{
		Name: "lib-gpl", Version: "v3.2.1", Ecosystem: "gomod", Direct: false,
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
	})
	r.Add(scanner.Dependency{
		Name: "lib-agpl", Version: "v2.0.0", Ecosystem: "gomod", Direct: true,
		Licenses: []scanner.License{scanner.NewLicense("AGPL-3.0", "")},
	})
	return r
}

func TestTableIncludesScanPath(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Table(&buf, sampleResult()))
	require.Contains(t, buf.String(), "/some/project")
}

func TestTableListsDetectors(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Table(&buf, sampleResult()))
	require.Contains(t, buf.String(), "Detectors: gomod")
}

func TestTableContainsAllDependencies(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Table(&buf, sampleResult()))

	out := buf.String()
	require.Contains(t, out, "lib-mit")
	require.Contains(t, out, "lib-gpl")
	require.Contains(t, out, "lib-agpl")
}

func TestTableSortsByRiskDescending(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Table(&buf, sampleResult()))

	out := buf.String()
	// AGPL (Viral) should appear before GPL (Strong), which appears before MIT (Permissive).
	agplPos := strings.Index(out, "lib-agpl")
	gplPos := strings.Index(out, "lib-gpl")
	mitPos := strings.Index(out, "lib-mit")
	require.True(t, agplPos < gplPos, "AGPL must sort before GPL: agpl=%d gpl=%d", agplPos, gplPos)
	require.True(t, gplPos < mitPos, "GPL must sort before MIT: gpl=%d mit=%d", gplPos, mitPos)
}

func TestTableShowsRiskEmojis(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Table(&buf, sampleResult()))

	out := buf.String()
	require.Contains(t, out, "✅") // MIT
	require.Contains(t, out, "🔴") // GPL
	require.Contains(t, out, "❌") // AGPL
}

func TestTableShowsDirectIndirectMarker(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Table(&buf, sampleResult()))

	out := buf.String()
	require.Contains(t, out, "yes") // direct
	require.Contains(t, out, "no")  // indirect
}

func TestTableRendersSummary(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Table(&buf, sampleResult()))

	out := buf.String()
	require.Contains(t, out, "Summary:")
	require.Contains(t, out, "Permissive")
	require.Contains(t, out, "Strong Copyleft")
	require.Contains(t, out, "Viral / Problematic")
}

func TestTableHandlesEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Table(&buf, scanner.NewResult("/empty")))
	require.Contains(t, buf.String(), "No dependencies found")
}

func TestTableRendersDetectorErrors(t *testing.T) {
	r := scanner.NewResult("/x")
	r.Errors = []string{"gomod: read failed: permission denied"}

	var buf bytes.Buffer
	require.NoError(t, Table(&buf, r))
	require.Contains(t, buf.String(), "Detector errors:")
	require.Contains(t, buf.String(), "permission denied")
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errFailingWrite
}

var errFailingWrite = &writerError{msg: "writer failed"}

type writerError struct{ msg string }

func (e *writerError) Error() string { return e.msg }

func TestTablePropagatesWriterErrors(t *testing.T) {
	err := Table(failingWriter{}, sampleResult())
	require.Error(t, err)
}
