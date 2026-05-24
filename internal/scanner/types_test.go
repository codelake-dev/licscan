package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRiskLevelString(t *testing.T) {
	cases := []struct {
		level RiskLevel
		want  string
	}{
		{RiskUnknown, "Unknown"},
		{RiskPermissive, "Permissive"},
		{RiskWeakCopyleft, "Weak Copyleft"},
		{RiskStrongCopyleft, "Strong Copyleft"},
		{RiskViral, "Viral / Problematic"},
		{RiskLevel(999), "Unknown"}, // unknown enum falls back gracefully
	}
	for _, c := range cases {
		require.Equal(t, c.want, c.level.String())
	}
}

func TestRiskLevelEmoji(t *testing.T) {
	require.Equal(t, "✅", RiskPermissive.Emoji())
	require.Equal(t, "⚠️", RiskWeakCopyleft.Emoji())
	require.Equal(t, "🔴", RiskStrongCopyleft.Emoji())
	require.Equal(t, "❌", RiskViral.Emoji())
	require.Equal(t, "❓", RiskUnknown.Emoji())
	require.Equal(t, "❓", RiskLevel(999).Emoji())
}

func TestRiskLevelOrdering(t *testing.T) {
	// Order matters for PrimaryRisk() which picks the max.
	require.True(t, RiskUnknown < RiskPermissive)
	require.True(t, RiskPermissive < RiskWeakCopyleft)
	require.True(t, RiskWeakCopyleft < RiskStrongCopyleft)
	require.True(t, RiskStrongCopyleft < RiskViral)
}

func TestDependencyPrimaryRiskPicksHighest(t *testing.T) {
	dep := Dependency{
		Licenses: []License{
			NewLicense("MIT", ""),
			NewLicense("GPL-3.0", ""),
			NewLicense("Apache-2.0", ""),
		},
	}
	require.Equal(t, RiskStrongCopyleft, dep.PrimaryRisk())
	require.Equal(t, "GPL-3.0", dep.PrimaryLicense())
}

func TestDependencyPrimaryRiskOnEmptyLicenses(t *testing.T) {
	dep := Dependency{}
	require.Equal(t, RiskUnknown, dep.PrimaryRisk())
	require.Equal(t, "Unknown", dep.PrimaryLicense())
}

func TestDependencyPrimaryLicenseSinglePermissive(t *testing.T) {
	dep := Dependency{Licenses: []License{NewLicense("MIT", "")}}
	require.Equal(t, "MIT", dep.PrimaryLicense())
	require.Equal(t, RiskPermissive, dep.PrimaryRisk())
}

func TestNewResultInitializesAllRiskBuckets(t *testing.T) {
	r := NewResult("/tmp/x")
	require.Equal(t, "/tmp/x", r.ScanPath)
	require.Contains(t, r.Summary, "Unknown")
	require.Contains(t, r.Summary, "Permissive")
	require.Contains(t, r.Summary, "Weak Copyleft")
	require.Contains(t, r.Summary, "Strong Copyleft")
	require.Contains(t, r.Summary, "Viral / Problematic")
	for _, count := range r.Summary {
		require.Equal(t, 0, count)
	}
}

func TestResultAddIncrementsCorrectBucket(t *testing.T) {
	r := NewResult(".")
	r.Add(Dependency{Licenses: []License{NewLicense("MIT", "")}})
	r.Add(Dependency{Licenses: []License{NewLicense("AGPL-3.0", "")}})
	r.Add(Dependency{Licenses: []License{NewLicense("GPL-3.0", "")}})
	r.Add(Dependency{}) // no licenses → Unknown

	require.Equal(t, 1, r.Summary["Permissive"])
	require.Equal(t, 1, r.Summary["Viral / Problematic"])
	require.Equal(t, 1, r.Summary["Strong Copyleft"])
	require.Equal(t, 1, r.Summary["Unknown"])
	require.Len(t, r.Dependencies, 4)
}

func TestResultHasViolationsTrue(t *testing.T) {
	r := NewResult(".")
	r.Add(Dependency{Licenses: []License{NewLicense("GPL-3.0", "")}})
	require.True(t, r.HasViolations())
}

func TestResultHasViolationsFalseOnPermissiveOnly(t *testing.T) {
	r := NewResult(".")
	r.Add(Dependency{Licenses: []License{NewLicense("MIT", "")}})
	r.Add(Dependency{Licenses: []License{NewLicense("Apache-2.0", "")}})
	require.False(t, r.HasViolations())
}

func TestResultHasViolationsFalseOnWeakCopyleftAlone(t *testing.T) {
	// LGPL is weak copyleft — not a violation by default.
	r := NewResult(".")
	r.Add(Dependency{Licenses: []License{NewLicense("LGPL-3.0", "")}})
	require.False(t, r.HasViolations())
}
