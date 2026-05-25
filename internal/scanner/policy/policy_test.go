package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, PolicyFile), []byte(content), 0o644))
	return dir
}

// ── Default policy ──────────────────────────────────────────────

func TestDefaultDeniesStrongCopyleftAndViral(t *testing.T) {
	p := Default()
	require.Contains(t, p.Deny, "GPL-3.0")
	require.Contains(t, p.Deny, "AGPL-3.0")
	require.Contains(t, p.Deny, "SSPL-1.0")
	require.True(t, p.IsDefault())
}

func TestDefaultWarnsOnWeakCopyleft(t *testing.T) {
	p := Default()
	require.Contains(t, p.Warn, "LGPL-3.0")
	require.Contains(t, p.Warn, "MPL-2.0")
}

func TestDefaultDoesNotDenyPermissive(t *testing.T) {
	p := Default()
	for _, lic := range []string{"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"} {
		require.NotContains(t, p.Deny, lic)
		require.NotContains(t, p.Warn, lic)
	}
}

// ── Loading from disk ──────────────────────────────────────────

func TestLoadReturnsDefaultWhenFileAbsent(t *testing.T) {
	p, err := Load(t.TempDir())
	require.NoError(t, err)
	require.True(t, p.IsDefault(), "absent .licscan.yml must return default policy")
}

func TestLoadParsesFullSchema(t *testing.T) {
	dir := writePolicy(t, `
deny:
  - AGPL-3.0
  - GPL-2.0

warn:
  - GPL-3.0

allow_exceptions:
  - package: github.com/legacy/gpl-lib
    reason: only used in tests, never bundled
`)
	p, err := Load(dir)
	require.NoError(t, err)
	require.False(t, p.IsDefault(), "loaded policy must not be default")
	require.Equal(t, []string{"AGPL-3.0", "GPL-2.0"}, p.Deny)
	require.Equal(t, []string{"GPL-3.0"}, p.Warn)
	require.Len(t, p.AllowExceptions, 1)
	require.Equal(t, "github.com/legacy/gpl-lib", p.AllowExceptions[0].Package)
	require.Equal(t, "only used in tests, never bundled", p.AllowExceptions[0].Reason)
}

func TestLoadErrorsOnMalformedYAML(t *testing.T) {
	dir := writePolicy(t, "deny: [unterminated\nthis is not yaml\n@@@")
	_, err := Load(dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), PolicyFile)
}

func TestLoadAcceptsEmptyFile(t *testing.T) {
	dir := writePolicy(t, "")
	p, err := Load(dir)
	require.NoError(t, err)
	require.False(t, p.IsDefault(), "empty .licscan.yml is still a loaded policy (not default)")
	// Per-field inherit: missing keys fall back to default lists.
	require.NotEmpty(t, p.Deny, "empty file should inherit default deny list")
	require.NotEmpty(t, p.Warn, "empty file should inherit default warn list")
	require.Contains(t, p.Deny, "AGPL-3.0")
	require.Contains(t, p.Warn, "LGPL-3.0")
}

// ── Per-field inherit from defaults ────────────────────────────

func TestLoadInheritsDefaultsWhenOnlyManufacturerSet(t *testing.T) {
	// Common case: .licscan.yml exists purely to set manufacturer/product
	// for CRA evidence. deny/warn keys are absent → inherit defaults
	// (not "explicitly allow everything", which was the pre-fix behaviour
	// reported in licscan#8).
	dir := writePolicy(t, `
manufacturer:
  name: Acme GmbH
  email: security@acme.example
  url: https://acme.example
  country: DE
product:
  name: legacy-app
  version: 1.0.0
`)
	p, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, "Acme GmbH", p.Manufacturer.Name)
	require.Contains(t, p.Deny, "GPL-3.0", "deny list must be inherited from defaults")
	require.Contains(t, p.Deny, "AGPL-3.0")
	require.Contains(t, p.Warn, "LGPL-3.0", "warn list must be inherited from defaults")
}

func TestLoadExplicitEmptyDenyMeansAllowEverything(t *testing.T) {
	// Explicit `deny: []` is the escape-hatch for projects that want to
	// turn off the default deny list entirely. The key is *present* (so
	// the slice is non-nil empty, not nil) → no inherit.
	dir := writePolicy(t, `
deny: []
warn:
  - LGPL-3.0
`)
	p, err := Load(dir)
	require.NoError(t, err)
	require.NotNil(t, p.Deny, "explicit empty list must stay non-nil")
	require.Empty(t, p.Deny, "explicit `deny: []` should NOT inherit defaults")
	require.Equal(t, []string{"LGPL-3.0"}, p.Warn,
		"warn was explicitly set, should not inherit defaults either")
}

func TestLoadOverridesOneFieldInheritsOther(t *testing.T) {
	// User sets only deny, omits warn → deny is custom, warn inherits.
	dir := writePolicy(t, `
deny:
  - MIT
`)
	p, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"MIT"}, p.Deny, "custom deny list preserved as-is")
	require.NotEmpty(t, p.Warn, "warn was absent, should inherit defaults")
	require.Contains(t, p.Warn, "LGPL-3.0")
}

func TestLoadExplicitFullOverride(t *testing.T) {
	// User explicitly sets both deny + warn → no inherit at all.
	dir := writePolicy(t, `
deny:
  - AGPL-3.0
warn:
  - GPL-3.0
`)
	p, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"AGPL-3.0"}, p.Deny)
	require.Equal(t, []string{"GPL-3.0"}, p.Warn)
}

func TestLoadDefaultPolicyAppliesAGPLDeny(t *testing.T) {
	// End-to-end: a minimal .licscan.yml + an AGPL-3.0 dep → ✗ deny.
	// Was the failure mode reported in licscan#8.
	dir := writePolicy(t, `
manufacturer:
  name: Acme GmbH
`)
	p, err := Load(dir)
	require.NoError(t, err)

	r := resultWithDeps(depWith("evil-lib", "AGPL-3.0"))
	p.Apply(r)
	require.Equal(t, VerdictDeny, r.Dependencies[0].Verdict)
}

// ── Manufacturer + Product blocks (EU CRA evidence) ─────────────

func TestLoadParsesManufacturerBlock(t *testing.T) {
	dir := writePolicy(t, `
manufacturer:
  name: Acme GmbH
  email: security@acme.example
  url: https://acme.example
  country: DE
`)
	p, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, "Acme GmbH", p.Manufacturer.Name)
	require.Equal(t, "security@acme.example", p.Manufacturer.Email)
	require.Equal(t, "https://acme.example", p.Manufacturer.URL)
	require.Equal(t, "DE", p.Manufacturer.Country)
	require.False(t, p.Manufacturer.IsZero())
}

func TestLoadParsesProductBlock(t *testing.T) {
	dir := writePolicy(t, `
product:
  name: my-app
  version: 1.2.3
  category: important
  support_lifecycle_end: "2031-05-24"
`)
	p, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, "my-app", p.Product.Name)
	require.Equal(t, "1.2.3", p.Product.Version)
	require.Equal(t, "important", p.Product.Category)
	require.Equal(t, "2031-05-24", p.Product.SupportLifecycleEnd)
	require.False(t, p.Product.IsZero())
}

func TestManufacturerIsZeroOnUnsetBlock(t *testing.T) {
	p := Default()
	require.True(t, p.Manufacturer.IsZero(), "default policy has no manufacturer set")
}

func TestProductIsZeroOnUnsetBlock(t *testing.T) {
	p := Default()
	require.True(t, p.Product.IsZero(), "default policy has no product set")
}

// ── Apply (per-dep classification) ──────────────────────────────

func resultWithDeps(deps ...scanner.Dependency) *scanner.Result {
	r := scanner.NewResult("/x")
	for _, d := range deps {
		r.Add(d)
	}
	return r
}

func depWith(name, spdx string) scanner.Dependency {
	return scanner.Dependency{
		Name: name, Version: "1.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense(spdx, "")},
	}
}

func TestApplyDeniesDenyListedLicense(t *testing.T) {
	r := resultWithDeps(depWith("x", "AGPL-3.0"))
	Default().Apply(r)

	require.Equal(t, VerdictDeny, r.Dependencies[0].Verdict)
	require.Contains(t, r.Dependencies[0].Reason, "AGPL-3.0")
	require.Contains(t, r.Dependencies[0].Reason, "deny")
}

func TestApplyWarnsWarnListedLicense(t *testing.T) {
	r := resultWithDeps(depWith("x", "LGPL-3.0"))
	Default().Apply(r)

	require.Equal(t, VerdictWarn, r.Dependencies[0].Verdict)
	require.Contains(t, r.Dependencies[0].Reason, "LGPL-3.0")
}

func TestApplyAllowsPermissive(t *testing.T) {
	r := resultWithDeps(depWith("x", "MIT"))
	Default().Apply(r)

	require.Equal(t, VerdictAllow, r.Dependencies[0].Verdict)
	require.Empty(t, r.Dependencies[0].Reason, "allow verdict carries no reason")
}

func TestApplyAllowsUnknown(t *testing.T) {
	// Unknown is not blocked by default — humans must triage.
	r := resultWithDeps(depWith("x", "Unknown"))
	Default().Apply(r)
	require.Equal(t, VerdictAllow, r.Dependencies[0].Verdict)
}

func TestApplyExemptsPackagesInAllowExceptions(t *testing.T) {
	p := &Policy{
		Deny:            []string{"AGPL-3.0"},
		AllowExceptions: []Exception{{Package: "x", Reason: "test-only"}},
	}
	// Even though AGPL is denied, package "x" is exempted.
	r := resultWithDeps(depWith("x", "AGPL-3.0"))
	p.Apply(r)

	require.Equal(t, VerdictExempt, r.Dependencies[0].Verdict)
	require.Equal(t, "test-only", r.Dependencies[0].Reason)
}

func TestApplyDenyTrumpsWarnAcrossMultipleLicenses(t *testing.T) {
	// One dep with two licenses: MIT (allow) + GPL-3.0 (deny) → deny wins.
	dep := scanner.Dependency{
		Name: "multi", Version: "1.0", Ecosystem: "npm",
		Licenses: []scanner.License{
			scanner.NewLicense("MIT", ""),
			scanner.NewLicense("GPL-3.0", ""),
		},
	}
	r := resultWithDeps(dep)
	Default().Apply(r)

	require.Equal(t, VerdictDeny, r.Dependencies[0].Verdict)
	require.Contains(t, r.Dependencies[0].Reason, "GPL-3.0")
}

func TestApplyMatchingIsCaseInsensitive(t *testing.T) {
	p := &Policy{Deny: []string{"agpl-3.0"}}      // lower-case in policy
	r := resultWithDeps(depWith("x", "AGPL-3.0")) // upper-case on dep
	p.Apply(r)
	require.Equal(t, VerdictDeny, r.Dependencies[0].Verdict)
}

func TestApplyTolerantOfNilResult(t *testing.T) {
	// Must not panic.
	Default().Apply(nil)
}

func TestApplyTrimsWhitespaceInPolicy(t *testing.T) {
	p := &Policy{Deny: []string{"  AGPL-3.0  "}}
	r := resultWithDeps(depWith("x", "AGPL-3.0"))
	p.Apply(r)
	require.Equal(t, VerdictDeny, r.Dependencies[0].Verdict)
}

// ── Verdict counting + violation detection ──────────────────────

func TestCountByVerdictBreakdown(t *testing.T) {
	r := resultWithDeps(
		depWith("a", "MIT"),
		depWith("b", "MIT"),
		depWith("c", "LGPL-3.0"),
		depWith("d", "AGPL-3.0"),
		depWith("e", "AGPL-3.0"),
	)
	Default().Apply(r)

	counts := CountByVerdict(r)
	require.Equal(t, 2, counts[VerdictAllow])
	require.Equal(t, 1, counts[VerdictWarn])
	require.Equal(t, 2, counts[VerdictDeny])
	require.Equal(t, 0, counts[VerdictExempt])
}

func TestCountByVerdictHandlesNil(t *testing.T) {
	counts := CountByVerdict(nil)
	require.Equal(t, 0, counts[VerdictDeny])
}

func TestHasDenialsTrueOnDeny(t *testing.T) {
	r := resultWithDeps(depWith("x", "AGPL-3.0"))
	Default().Apply(r)
	require.True(t, HasDenials(r))
}

func TestHasDenialsFalseOnWarnOnly(t *testing.T) {
	r := resultWithDeps(depWith("x", "LGPL-3.0"))
	Default().Apply(r)
	require.False(t, HasDenials(r))
}

func TestHasDenialsFalseOnExemptedDeny(t *testing.T) {
	p := &Policy{
		Deny:            []string{"AGPL-3.0"},
		AllowExceptions: []Exception{{Package: "x", Reason: "test-only"}},
	}
	r := resultWithDeps(depWith("x", "AGPL-3.0"))
	p.Apply(r)
	require.False(t, HasDenials(r), "exempted denies must not count as denials")
}
