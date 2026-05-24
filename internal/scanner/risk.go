package scanner

import "strings"

// riskMap maps SPDX identifiers to risk levels. Keys are normalised to
// lower case for case-insensitive lookup. Coverage is intentionally
// pragmatic — the long tail of obscure SPDX IDs falls through to
// RiskUnknown, which is the correct behaviour (humans should classify
// anything the tool doesn't recognise).
var riskMap = map[string]RiskLevel{
	// Permissive — no copyleft, attribution-only.
	"mit":           RiskPermissive,
	"apache-2.0":    RiskPermissive,
	"apache 2.0":    RiskPermissive,
	"bsd-2-clause":  RiskPermissive,
	"bsd-3-clause":  RiskPermissive,
	"bsd-4-clause":  RiskPermissive, // technically permissive though has issues
	"isc":           RiskPermissive,
	"unlicense":     RiskPermissive,
	"0bsd":          RiskPermissive,
	"zlib":          RiskPermissive,
	"cc0-1.0":       RiskPermissive,
	"wtfpl":         RiskPermissive,
	"x11":           RiskPermissive,
	"python-2.0":    RiskPermissive,
	"postgresql":    RiskPermissive,
	"blueoak-1.0.0": RiskPermissive,
	"artistic-2.0":  RiskPermissive,
	"upl-1.0":       RiskPermissive,
	"ofl-1.1":       RiskPermissive, // SIL Open Font License — common in font packages

	// Weak copyleft — file-level / library-boundary copyleft.
	"lgpl-2.1":          RiskWeakCopyleft,
	"lgpl-2.1-only":     RiskWeakCopyleft,
	"lgpl-2.1-or-later": RiskWeakCopyleft,
	"lgpl-3.0":          RiskWeakCopyleft,
	"lgpl-3.0-only":     RiskWeakCopyleft,
	"lgpl-3.0-or-later": RiskWeakCopyleft,
	"mpl-1.1":           RiskWeakCopyleft,
	"mpl-2.0":           RiskWeakCopyleft,
	"epl-1.0":           RiskWeakCopyleft,
	"epl-2.0":           RiskWeakCopyleft,
	"cddl-1.0":          RiskWeakCopyleft,
	"cddl-1.1":          RiskWeakCopyleft,
	"eupl-1.1":          RiskWeakCopyleft,
	"eupl-1.2":          RiskWeakCopyleft,

	// Strong copyleft — full derivative-work copyleft.
	"gpl-2.0":          RiskStrongCopyleft,
	"gpl-2.0-only":     RiskStrongCopyleft,
	"gpl-2.0-or-later": RiskStrongCopyleft,
	"gpl-3.0":          RiskStrongCopyleft,
	"gpl-3.0-only":     RiskStrongCopyleft,
	"gpl-3.0-or-later": RiskStrongCopyleft,

	// Viral / problematic — network-copyleft or commercial-restrictive.
	"agpl-3.0":            RiskViral,
	"agpl-3.0-only":       RiskViral,
	"agpl-3.0-or-later":   RiskViral,
	"sspl-1.0":            RiskViral,
	"bsl-1.1":             RiskViral, // Business Source License (NOT the BSL OpenSSL pre-Apache)
	"busl-1.1":            RiskViral, // alternative spelling
	"commons-clause":      RiskViral,
	"elastic-2.0":         RiskViral,
	"elastic-license-2.0": RiskViral,
}

// ClassifyRisk returns the risk level for an SPDX identifier.
// Case-insensitive; unrecognised IDs return RiskUnknown.
func ClassifyRisk(spdxID string) RiskLevel {
	if spdxID == "" {
		return RiskUnknown
	}
	if r, ok := riskMap[strings.ToLower(strings.TrimSpace(spdxID))]; ok {
		return r
	}
	return RiskUnknown
}

// NewLicense builds a License with the risk fields pre-populated.
func NewLicense(spdxID, source string) License {
	risk := ClassifyRisk(spdxID)
	return License{
		SPDX:   spdxID,
		Risk:   risk,
		Risk_:  risk.String(),
		Source: source,
	}
}
