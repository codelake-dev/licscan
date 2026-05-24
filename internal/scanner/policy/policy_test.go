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
	require.Empty(t, p.Deny)
	require.Empty(t, p.Warn)
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
	p := &Policy{Deny: []string{"agpl-3.0"}} // lower-case in policy
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
