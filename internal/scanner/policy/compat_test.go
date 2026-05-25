package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestCheckCompatibilityFlagsMITvsGPL(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "safe-lib", Version: "1.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
		Verdict:  VerdictAllow,
	})
	r.Add(scanner.Dependency{
		Name: "gpl-lib", Version: "2.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
		Verdict:  VerdictDeny,
	})

	CheckCompatibility(r, "MIT")

	assert.Equal(t, VerdictAllow, r.Dependencies[0].Verdict)
	assert.Equal(t, VerdictIncompat, r.Dependencies[1].Verdict)
	assert.Contains(t, r.Dependencies[1].Reason, "incompatible with project license MIT")
}

func TestCheckCompatibilitySkipsExempt(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "exempt-gpl", Version: "1.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
		Verdict:  VerdictExempt, Reason: "test-only",
	})

	CheckCompatibility(r, "MIT")

	assert.Equal(t, VerdictExempt, r.Dependencies[0].Verdict, "exempt deps must not be overridden")
}

func TestCheckCompatibilityNoopWithoutProjectLicense(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "gpl-lib", Version: "1.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
		Verdict:  VerdictDeny,
	})

	CheckCompatibility(r, "")

	assert.Equal(t, VerdictDeny, r.Dependencies[0].Verdict, "should not change verdict without project license")
}

func TestCheckCompatibilityPermissiveIsAlwaysOK(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "mit-lib", Version: "1.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
		Verdict:  VerdictAllow,
	})
	r.Add(scanner.Dependency{
		Name: "apache-lib", Version: "2.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("Apache-2.0", "")},
		Verdict:  VerdictAllow,
	})

	CheckCompatibility(r, "MIT")

	assert.Equal(t, VerdictAllow, r.Dependencies[0].Verdict)
	assert.Equal(t, VerdictAllow, r.Dependencies[1].Verdict)
}

func TestCheckCompatibilityApacheVsGPL2(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "gpl2-lib", Version: "1.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("GPL-2.0", "")},
		Verdict:  VerdictDeny,
	})

	CheckCompatibility(r, "Apache-2.0")

	assert.Equal(t, VerdictIncompat, r.Dependencies[0].Verdict)
	assert.Contains(t, r.Dependencies[0].Reason, "incompatible")
}

func TestCheckCompatibilityGPL3AllowsLGPL(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "lgpl-lib", Version: "1.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("LGPL-3.0", "")},
		Verdict:  VerdictWarn,
	})

	CheckCompatibility(r, "GPL-3.0")

	assert.Equal(t, VerdictWarn, r.Dependencies[0].Verdict, "LGPL is compatible with GPL-3.0")
}

func TestCheckCompatibilityUnknownProjectLicenseIsNoop(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "gpl-lib", Version: "1.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
		Verdict:  VerdictDeny,
	})

	CheckCompatibility(r, "CustomLicense-1.0")

	assert.Equal(t, VerdictDeny, r.Dependencies[0].Verdict, "unknown project license should not change verdicts")
}

func TestDetectProjectLicensePrefersYAML(t *testing.T) {
	pol := &Policy{ProjectLicense: "MIT"}
	result := DetectProjectLicense("/nonexistent", pol)
	assert.Equal(t, "MIT", result)
}

func TestDetectProjectLicenseFallsBackToFile(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("MIT License\n\nPermission is hereby granted..."), 0o644)
	require.NoError(t, err)

	pol := &Policy{}
	result := DetectProjectLicense(dir, pol)
	assert.Equal(t, "MIT", result)
}

func TestDetectProjectLicenseApache(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("Apache License, Version 2.0\n\nhttp://www.apache.org/licenses/"), 0o644)
	require.NoError(t, err)

	pol := &Policy{}
	result := DetectProjectLicense(dir, pol)
	assert.Equal(t, "Apache-2.0", result)
}

func TestHasDenialsIncludesIncompat(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "lib", Version: "1.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("GPL-3.0", "")},
		Verdict:  VerdictIncompat,
	})

	assert.True(t, HasDenials(r), "incompatible should count as a denial for CI mode")
}
