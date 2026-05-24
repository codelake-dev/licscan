package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyRiskPermissive(t *testing.T) {
	for _, id := range []string{
		"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "0BSD", "Zlib",
	} {
		require.Equal(t, RiskPermissive, ClassifyRisk(id), "ID: %s", id)
	}
}

func TestClassifyRiskWeakCopyleft(t *testing.T) {
	for _, id := range []string{
		"LGPL-2.1", "LGPL-3.0", "LGPL-2.1-or-later", "LGPL-3.0-or-later",
		"MPL-2.0", "EPL-2.0", "CDDL-1.0", "EUPL-1.2",
	} {
		require.Equal(t, RiskWeakCopyleft, ClassifyRisk(id), "ID: %s", id)
	}
}

func TestClassifyRiskStrongCopyleft(t *testing.T) {
	for _, id := range []string{
		"GPL-2.0", "GPL-3.0", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
	} {
		require.Equal(t, RiskStrongCopyleft, ClassifyRisk(id), "ID: %s", id)
	}
}

func TestClassifyRiskViral(t *testing.T) {
	for _, id := range []string{
		"AGPL-3.0", "AGPL-3.0-or-later", "SSPL-1.0", "BSL-1.1", "BUSL-1.1",
		"Commons-Clause", "Elastic-2.0",
	} {
		require.Equal(t, RiskViral, ClassifyRisk(id), "ID: %s", id)
	}
}

func TestClassifyRiskCaseInsensitive(t *testing.T) {
	require.Equal(t, RiskPermissive, ClassifyRisk("mit"))
	require.Equal(t, RiskPermissive, ClassifyRisk("MIT"))
	require.Equal(t, RiskPermissive, ClassifyRisk("  Mit  "))
	require.Equal(t, RiskStrongCopyleft, ClassifyRisk("gpl-3.0"))
}

func TestClassifyRiskUnknownForEmpty(t *testing.T) {
	require.Equal(t, RiskUnknown, ClassifyRisk(""))
	require.Equal(t, RiskUnknown, ClassifyRisk("   "))
}

func TestClassifyRiskUnknownForObscure(t *testing.T) {
	require.Equal(t, RiskUnknown, ClassifyRisk("SomeRandomMadeUpLicense-9.9"))
	require.Equal(t, RiskUnknown, ClassifyRisk("MyCompany-Internal-1.0"))
}

func TestNewLicensePopulatesAllFields(t *testing.T) {
	lic := NewLicense("MIT", "/path/to/LICENSE")
	require.Equal(t, "MIT", lic.SPDX)
	require.Equal(t, RiskPermissive, lic.Risk)
	require.Equal(t, "Permissive", lic.Risk_)
	require.Equal(t, "/path/to/LICENSE", lic.Source)
}

func TestNewLicenseUnknown(t *testing.T) {
	lic := NewLicense("", "")
	require.Equal(t, RiskUnknown, lic.Risk)
	require.Equal(t, "Unknown", lic.Risk_)
}
