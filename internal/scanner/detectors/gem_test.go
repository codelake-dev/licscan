package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

type stubGemResolver struct {
	results map[string]struct{ spdx, source string }
}

func (s stubGemResolver) Resolve(name, _ string) (string, string) {
	if r, ok := s.results[name]; ok {
		return r.spdx, r.source
	}
	return "", ""
}

// ── basic detection ────────────────────────────────────────────

func TestGemName(t *testing.T) {
	require.Equal(t, "gem", (&Gem{}).Name())
}

func TestGemReturnsNotFoundWhenNoGemfileLock(t *testing.T) {
	found, deps, err := (&Gem{}).Detect(t.TempDir())
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, deps)
}

// ── Gemfile.lock parsing ───────────────────────────────────────

const sampleGemfileLock = `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.1.0)
      actionview (= 7.1.0)
      activesupport (= 7.1.0)
    actionview (7.1.0)
      activesupport (= 7.1.0)
    activesupport (7.1.0)
      concurrent-ruby (~> 1.0, >= 1.0.2)
    concurrent-ruby (1.2.2)
    nokogiri (1.15.4-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.1)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  rails (~> 7.1)
  nokogiri
  rspec-rails

RUBY VERSION
   ruby 3.2.2p53

BUNDLED WITH
   2.4.10
`

func TestGemParsesAllSpecs(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Gemfile.lock": sampleGemfileLock,
	})
	det := &Gem{Resolver: stubGemResolver{}}
	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 6, "actionpack + actionview + activesupport + concurrent-ruby + nokogiri + racc")
}

func TestGemMarksDirectVsTransitive(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Gemfile.lock": sampleGemfileLock,
	})
	det := &Gem{Resolver: stubGemResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	direct := map[string]bool{}
	for _, d := range deps {
		direct[d.Name] = d.Direct
	}
	require.True(t, direct["nokogiri"], "nokogiri in DEPENDENCIES → direct")
	require.False(t, direct["racc"], "racc only in nested requirements → transitive")
	require.False(t, direct["concurrent-ruby"], "concurrent-ruby only nested → transitive")
}

func TestGemHandlesPlatformSuffixInSpec(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Gemfile.lock": sampleGemfileLock,
	})
	det := &Gem{Resolver: stubGemResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	for _, d := range deps {
		if d.Name == "nokogiri" {
			// Version captured as-is from the lockfile — incl. platform suffix.
			require.Contains(t, d.Version, "1.15.4")
		}
	}
}

func TestGemMarksUnresolvedAsUnknown(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Gemfile.lock": sampleGemfileLock,
	})
	det := &Gem{Resolver: stubGemResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	for _, d := range deps {
		require.Equal(t, "Unknown", d.PrimaryLicense())
		require.NotEmpty(t, d.Notes)
	}
}

func TestGemUsesResolverForLicenses(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Gemfile.lock": sampleGemfileLock,
	})
	det := &Gem{Resolver: stubGemResolver{results: map[string]struct{ spdx, source string }{
		"actionpack":      {"MIT", "stub"},
		"actionview":      {"MIT", "stub"},
		"activesupport":   {"MIT", "stub"},
		"concurrent-ruby": {"MIT", "stub"},
		"nokogiri":        {"MIT", "stub"},
		"racc":            {"MIT", "stub"},
	}}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	for _, d := range deps {
		require.Equal(t, "MIT", d.PrimaryLicense())
		require.Equal(t, scanner.RiskPermissive, d.PrimaryRisk())
	}
}

func TestGemEmptyLockfileProducesEmptyResult(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Gemfile.lock": "GEM\n  specs:\n\nDEPENDENCIES\n",
	})
	det := &Gem{Resolver: stubGemResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.Empty(t, deps)
}

// ── BundlerOrGemHomeResolver ───────────────────────────────────

func TestBundlerResolverReadsLicenseFromGemspec(t *testing.T) {
	project := t.TempDir()
	gemsDir := filepath.Join(project, "vendor", "bundle", "ruby", "3.2.0", "gems", "rails-7.1.0")
	require.NoError(t, os.MkdirAll(gemsDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(gemsDir, "rails.gemspec"),
		[]byte(`Gem::Specification.new do |s|
  s.name = "rails"
  s.version = "7.1.0"
  s.license = "MIT"
end
`),
		0o644))

	r := &BundlerOrGemHomeResolver{ProjectRoot: project}
	spdx, source := r.Resolve("rails", "7.1.0")
	require.Equal(t, "MIT", spdx)
	require.Contains(t, source, "rails.gemspec")
}

func TestBundlerResolverHandlesArrayLicenses(t *testing.T) {
	project := t.TempDir()
	gemsDir := filepath.Join(project, "vendor", "bundle", "ruby", "3.2.0", "gems", "rubygem-1.0.0")
	require.NoError(t, os.MkdirAll(gemsDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(gemsDir, "rubygem.gemspec"),
		[]byte(`Gem::Specification.new do |spec|
  spec.licenses = ["MIT", "Apache-2.0"]
end
`),
		0o644))

	r := &BundlerOrGemHomeResolver{ProjectRoot: project}
	spdx, _ := r.Resolve("rubygem", "1.0.0")
	require.Equal(t, "MIT", spdx, "first license in array wins")
}

func TestBundlerResolverFallsBackToLicenseFile(t *testing.T) {
	project := t.TempDir()
	gemsDir := filepath.Join(project, "vendor", "bundle", "ruby", "3.2.0", "gems", "weirdgem-1.0.0")
	require.NoError(t, os.MkdirAll(gemsDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(gemsDir, "LICENSE"),
		[]byte("Apache License\nVersion 2.0"),
		0o644))

	r := &BundlerOrGemHomeResolver{ProjectRoot: project}
	spdx, source := r.Resolve("weirdgem", "1.0.0")
	require.Equal(t, "Apache-2.0", spdx)
	require.Contains(t, source, "LICENSE")
}

func TestBundlerResolverUsesGEMHomeWhenVendorEmpty(t *testing.T) {
	gemHome := t.TempDir()
	gemsDir := filepath.Join(gemHome, "gems", "rails-7.1.0")
	require.NoError(t, os.MkdirAll(gemsDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(gemsDir, "rails.gemspec"),
		[]byte(`Gem::Specification.new do |s|
  s.license = "MIT"
end
`),
		0o644))

	r := &BundlerOrGemHomeResolver{GemHome: gemHome}
	spdx, _ := r.Resolve("rails", "7.1.0")
	require.Equal(t, "MIT", spdx)
}

func TestBundlerResolverHandlesEmptyInputs(t *testing.T) {
	r := &BundlerOrGemHomeResolver{}
	spdx, _ := r.Resolve("x", "1.0")
	require.Equal(t, "", spdx)
	spdx, _ = r.Resolve("", "1.0")
	require.Equal(t, "", spdx)
	spdx, _ = r.Resolve("x", "")
	require.Equal(t, "", spdx)
}

// ── extractLicenseFromGemspec ──────────────────────────────────

func TestExtractLicenseFromGemspecSingleString(t *testing.T) {
	source := `Gem::Specification.new do |s|
  s.license = "MIT"
end`
	require.Equal(t, "MIT", extractLicenseFromGemspec([]byte(source)))
}

func TestExtractLicenseFromGemspecArray(t *testing.T) {
	source := `  s.licenses = ["MIT", "Apache-2.0"]`
	require.Equal(t, "MIT", extractLicenseFromGemspec([]byte(source)))
}

func TestExtractLicenseFromGemspecSingleQuotes(t *testing.T) {
	source := `  s.license = 'BSD-3-Clause'`
	require.Equal(t, "BSD-3-Clause", extractLicenseFromGemspec([]byte(source)))
}

func TestExtractLicenseFromGemspecNoLicense(t *testing.T) {
	source := `Gem::Specification.new do |s|
  s.name = "foo"
end`
	require.Equal(t, "", extractLicenseFromGemspec([]byte(source)))
}

func TestFirstQuotedSubstringDouble(t *testing.T) {
	require.Equal(t, "hello", firstQuotedSubstring(`prefix "hello" suffix`))
}

func TestFirstQuotedSubstringSingle(t *testing.T) {
	require.Equal(t, "world", firstQuotedSubstring(`prefix 'world' suffix`))
}

func TestFirstQuotedSubstringEmpty(t *testing.T) {
	require.Equal(t, "", firstQuotedSubstring("no quotes here"))
}
