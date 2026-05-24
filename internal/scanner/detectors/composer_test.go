package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

type stubComposerResolver struct {
	results map[string]struct{ spdx, source string }
}

func (s stubComposerResolver) Resolve(name, _ string) (string, string) {
	if r, ok := s.results[name]; ok {
		return r.spdx, r.source
	}
	return "", ""
}

// ── basic detection ────────────────────────────────────────────

func TestComposerName(t *testing.T) {
	require.Equal(t, "composer", (&Composer{}).Name())
}

func TestComposerReturnsNotFoundWhenNoComposerJSON(t *testing.T) {
	found, deps, err := (&Composer{}).Detect(t.TempDir())
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, deps)
}

func TestComposerErrorsOnMalformedComposerJSON(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"composer.json": "{{{ invalid json",
	})
	found, _, err := (&Composer{}).Detect(dir)
	require.Error(t, err)
	require.True(t, found)
}

// ── composer.lock — primary path ───────────────────────────────

const sampleComposerLock = `{
	"packages": [
		{"name": "symfony/console", "version": "v6.4.0", "license": ["MIT"]},
		{"name": "monolog/monolog", "version": "3.5.0", "license": ["MIT"]},
		{"name": "doctrine/dbal", "version": "3.7.0", "license": ["MIT"]}
	],
	"packages-dev": [
		{"name": "phpunit/phpunit", "version": "10.5.0", "license": ["BSD-3-Clause"]},
		{"name": "some/gpl-tool", "version": "1.0", "license": ["GPL-3.0"]}
	]
}`

func TestComposerLockEmitsAllPackages(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"composer.json": `{"require": {"symfony/console": "^6.4"}, "require-dev": {"phpunit/phpunit": "^10.5"}}`,
		"composer.lock": sampleComposerLock,
	})

	det := &Composer{Resolver: stubComposerResolver{}}
	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 5)
}

func TestComposerLockUsesInlineLicense(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"composer.json": `{"require": {"symfony/console": "^6.4"}}`,
		"composer.lock": sampleComposerLock,
	})

	det := &Composer{Resolver: stubComposerResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	bySource := map[string]scanner.Dependency{}
	for _, d := range deps {
		bySource[d.Name] = d
	}
	require.Equal(t, "MIT", bySource["symfony/console"].PrimaryLicense())
	require.Equal(t, "GPL-3.0", bySource["some/gpl-tool"].PrimaryLicense())
	require.Equal(t, scanner.RiskStrongCopyleft, bySource["some/gpl-tool"].PrimaryRisk())
}

func TestComposerLockMarksDirectVsTransitive(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"composer.json": `{"require": {"symfony/console": "^6.4"}, "require-dev": {"phpunit/phpunit": "^10.5"}}`,
		"composer.lock": sampleComposerLock,
	})

	det := &Composer{Resolver: stubComposerResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	direct := map[string]bool{}
	for _, d := range deps {
		direct[d.Name] = d.Direct
	}
	require.True(t, direct["symfony/console"], "symfony/console listed in require → direct")
	require.True(t, direct["phpunit/phpunit"], "phpunit listed in require-dev → direct")
	require.False(t, direct["monolog/monolog"], "monolog not in composer.json → transitive")
	require.False(t, direct["some/gpl-tool"], "some/gpl-tool not in composer.json → transitive")
}

func TestComposerLockMarksUnresolvedAsUnknown(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"composer.json": `{"require": {"weird/pkg": "1.0"}}`,
		"composer.lock": `{"packages": [{"name": "weird/pkg", "version": "1.0", "license": []}], "packages-dev": []}`,
	})

	det := &Composer{Resolver: stubComposerResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.Len(t, deps, 1)
	require.Equal(t, "Unknown", deps[0].PrimaryLicense())
	require.NotEmpty(t, deps[0].Notes)
}

func TestComposerLockResolverFallbackWhenLicenseMissing(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"composer.json": `{"require": {"weird/pkg": "1.0"}}`,
		"composer.lock": `{"packages": [{"name": "weird/pkg", "version": "1.0", "license": []}], "packages-dev": []}`,
	})

	det := &Composer{Resolver: stubComposerResolver{results: map[string]struct{ spdx, source string }{
		"weird/pkg": {"Apache-2.0", "vendor-scanned"},
	}}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.Equal(t, "Apache-2.0", deps[0].PrimaryLicense())
}

// ── composer.json without lockfile ─────────────────────────────

func TestComposerWithoutLockfileEmitsOnlyDirectWithWarning(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"composer.json": `{
			"require": {"symfony/console": "^6.4", "monolog/monolog": "^3.0"},
			"require-dev": {"phpunit/phpunit": "^10.5"}
		}`,
	})

	det := &Composer{Resolver: stubComposerResolver{results: map[string]struct{ spdx, source string }{
		"symfony/console": {"MIT", "stub"},
		"monolog/monolog": {"MIT", "stub"},
		"phpunit/phpunit": {"BSD-3-Clause", "stub"},
	}}}
	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 3)

	for _, d := range deps {
		require.True(t, d.Direct)
		require.NotEmpty(t, d.Notes, "missing-lockfile must surface a warning Note")
	}
}

func TestComposerWithoutLockfileSkipsPlatformRequires(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"composer.json": `{
			"require": {
				"php": "^8.2",
				"ext-mbstring": "*",
				"lib-curl": "*",
				"symfony/console": "^6.4"
			}
		}`,
	})

	det := &Composer{Resolver: stubComposerResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.Len(t, deps, 1, "platform reqs (php, ext-*, lib-*) must not be treated as packages")
	require.Equal(t, "symfony/console", deps[0].Name)
}

// ── VendorResolver ─────────────────────────────────────────────

func TestVendorResolverReadsLicenseFromComposerJSONStringForm(t *testing.T) {
	vendor := t.TempDir()
	pkgDir := filepath.Join(vendor, "symfony", "console")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(pkgDir, "composer.json"),
		[]byte(`{"name": "symfony/console", "license": "MIT"}`),
		0o644))

	r := &VendorResolver{VendorDir: vendor}
	spdx, source := r.Resolve("symfony/console", "")
	require.Equal(t, "MIT", spdx)
	require.Contains(t, source, "composer.json")
}

func TestVendorResolverReadsLicenseFromComposerJSONArrayForm(t *testing.T) {
	vendor := t.TempDir()
	pkgDir := filepath.Join(vendor, "vendor", "multilicense")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(pkgDir, "composer.json"),
		[]byte(`{"name": "vendor/multilicense", "license": ["MIT", "Apache-2.0"]}`),
		0o644))

	r := &VendorResolver{VendorDir: vendor}
	spdx, _ := r.Resolve("vendor/multilicense", "")
	require.Equal(t, "MIT", spdx, "array form: first license wins")
}

func TestVendorResolverFallsBackToLicenseFile(t *testing.T) {
	vendor := t.TempDir()
	pkgDir := filepath.Join(vendor, "vendor", "weird")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(pkgDir, "composer.json"),
		[]byte(`{"name": "vendor/weird"}`),
		0o644))
	require.NoError(t, os.WriteFile(
		filepath.Join(pkgDir, "LICENSE"),
		[]byte("Apache License\nVersion 2.0"),
		0o644))

	r := &VendorResolver{VendorDir: vendor}
	spdx, source := r.Resolve("vendor/weird", "")
	require.Equal(t, "Apache-2.0", spdx)
	require.Contains(t, source, "LICENSE")
}

func TestVendorResolverHandlesMissingPackage(t *testing.T) {
	r := &VendorResolver{VendorDir: t.TempDir()}
	spdx, _ := r.Resolve("nonexistent/pkg", "")
	require.Equal(t, "", spdx)
}

func TestVendorResolverHandlesEmptyInputs(t *testing.T) {
	require.Equal(t, "", (&VendorResolver{}).resolveSpdx("any"))
	r := &VendorResolver{VendorDir: t.TempDir()}
	spdx, _ := r.Resolve("", "")
	require.Equal(t, "", spdx)
}

// resolveSpdx is a small accessor for the empty-VendorDir branch; the
// public Resolve already covers the empty-name branch above.
func (r *VendorResolver) resolveSpdx(name string) string {
	s, _ := r.Resolve(name, "")
	return s
}

// ── helpers ────────────────────────────────────────────────────

func TestFirstNonEmptyReturnsFirstNonZeroString(t *testing.T) {
	require.Equal(t, "MIT", firstNonEmpty([]string{"", "MIT", "Apache-2.0"}))
	require.Equal(t, "", firstNonEmpty([]string{"", ""}))
	require.Equal(t, "", firstNonEmpty(nil))
}
