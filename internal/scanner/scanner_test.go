package scanner

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubDetector is a fake Detector for unit-testing the orchestrator
// without needing real package-manager fixtures.
type stubDetector struct {
	name  string
	found bool
	deps  []Dependency
	err   error
}

func (s stubDetector) Name() string {
	return s.name
}

func (s stubDetector) Detect(_ string) (bool, []Dependency, error) {
	return s.found, s.deps, s.err
}

func TestScannerRunsAllDetectors(t *testing.T) {
	a := stubDetector{name: "a", found: true, deps: []Dependency{{Name: "dep-a", Licenses: []License{NewLicense("MIT", "")}}}}
	b := stubDetector{name: "b", found: true, deps: []Dependency{{Name: "dep-b", Licenses: []License{NewLicense("Apache-2.0", "")}}}}

	result, err := New(a, b).Scan(".")
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, result.Detectors)
	require.Len(t, result.Dependencies, 2)
	require.Equal(t, 2, result.Summary["Permissive"])
}

func TestScannerSkipsDetectorsThatFindNothing(t *testing.T) {
	a := stubDetector{name: "a", found: false}
	b := stubDetector{name: "b", found: true, deps: []Dependency{{Name: "dep", Licenses: []License{NewLicense("MIT", "")}}}}

	result, err := New(a, b).Scan(".")
	require.NoError(t, err)
	require.Equal(t, []string{"b"}, result.Detectors, "detector that found nothing must not be listed")
	require.Len(t, result.Dependencies, 1)
}

func TestScannerAccumulatesErrorsWithoutAborting(t *testing.T) {
	a := stubDetector{name: "a", err: errors.New("boom")}
	b := stubDetector{name: "b", found: true, deps: []Dependency{{Name: "dep", Licenses: []License{NewLicense("MIT", "")}}}}

	result, err := New(a, b).Scan(".")
	require.NoError(t, err, "individual detector errors must not abort the scan")
	require.Len(t, result.Errors, 1)
	require.Contains(t, result.Errors[0], "a:")
	require.Contains(t, result.Errors[0], "boom")
	require.Len(t, result.Dependencies, 1, "subsequent detectors must still run")
}

func TestScannerResolvesPathToAbsolute(t *testing.T) {
	result, err := New().Scan(".")
	require.NoError(t, err)
	require.True(t, len(result.ScanPath) > 0)
	require.True(t, result.ScanPath[0] == '/' || result.ScanPath[1] == ':', // unix abs or windows drive
		"scan path must be absolute, got: %s", result.ScanPath)
}

func TestScannerRegisterAddsDetector(t *testing.T) {
	s := New()
	require.Len(t, s.detectors, 0)
	s.Register(stubDetector{name: "x"})
	require.Len(t, s.detectors, 1)
}

func TestScannerEmptyHasNoDeps(t *testing.T) {
	result, err := New().Scan(".")
	require.NoError(t, err)
	require.Empty(t, result.Dependencies)
	require.Empty(t, result.Detectors)
	require.Empty(t, result.Errors)
}
