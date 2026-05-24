// Package scanner contains the dependency-and-license scanning engine.
//
// The engine is intentionally decoupled from CLI and output concerns:
// detectors emit Dependency records, the Scanner aggregates them into a
// Result, and the format package renders Results to terminal/JSON/HTML/etc.
package scanner

// RiskLevel classifies a license by the obligations it imposes on shipped
// software. Order matters: levels are listed from least to most restrictive
// so callers can compare with < / > if needed.
type RiskLevel int

const (
	// RiskUnknown — license could not be identified.
	RiskUnknown RiskLevel = iota
	// RiskPermissive — MIT, Apache-2.0, BSD variants, ISC, Unlicense.
	RiskPermissive
	// RiskWeakCopyleft — LGPL, MPL, EPL, CDDL.
	RiskWeakCopyleft
	// RiskStrongCopyleft — GPL variants.
	RiskStrongCopyleft
	// RiskViral — AGPL, SSPL, BSL, Commons Clause. Typically incompatible with
	// closed-source distribution.
	RiskViral
)

// String returns a human-readable label for the risk level.
func (r RiskLevel) String() string {
	switch r {
	case RiskPermissive:
		return "Permissive"
	case RiskWeakCopyleft:
		return "Weak Copyleft"
	case RiskStrongCopyleft:
		return "Strong Copyleft"
	case RiskViral:
		return "Viral / Problematic"
	default:
		return "Unknown"
	}
}

// Emoji returns the marker used in table output.
func (r RiskLevel) Emoji() string {
	switch r {
	case RiskPermissive:
		return "✅"
	case RiskWeakCopyleft:
		return "⚠️"
	case RiskStrongCopyleft:
		return "🔴"
	case RiskViral:
		return "❌"
	default:
		return "❓"
	}
}

// License represents one license attached to a dependency. A dependency
// may carry multiple licenses (OR / AND combinations are allowed by SPDX).
type License struct {
	SPDX  string    `json:"spdx"`            // SPDX identifier (e.g. "MIT") or "Unknown"
	Risk  RiskLevel `json:"-"`               // computed from SPDX
	Risk_ string    `json:"risk"`            // serialized risk label for JSON
	Source string   `json:"source,omitempty"` // where the license was detected (file path, inferred, etc.)
}

// Dependency is one third-party package found in a manifest.
type Dependency struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem string    `json:"ecosystem"`             // gomod, npm, composer, pip, gem, cargo, maven
	Manifest  string    `json:"manifest"`              // path to the manifest file relative to scan root
	Licenses  []License `json:"licenses"`
	Direct    bool      `json:"direct"`                // true if listed in the top-level manifest; false for transitive
	Notes     []string  `json:"notes,omitempty"`       // human-readable hints (e.g. "license file not found in module cache")
}

// PrimaryRisk returns the highest risk level across all attached licenses.
// Used for sorting and policy decisions when a dep carries multiple licenses.
func (d Dependency) PrimaryRisk() RiskLevel {
	max := RiskUnknown
	for _, l := range d.Licenses {
		if l.Risk > max {
			max = l.Risk
		}
	}
	return max
}

// PrimaryLicense returns the SPDX identifier of the highest-risk license,
// or "Unknown" if none.
func (d Dependency) PrimaryLicense() string {
	if len(d.Licenses) == 0 {
		return "Unknown"
	}
	primary := d.Licenses[0]
	for _, l := range d.Licenses[1:] {
		if l.Risk > primary.Risk {
			primary = l
		}
	}
	return primary.SPDX
}

// Result is a scan's aggregated output: every dependency found by every
// detector, plus a summary breakdown by risk level.
type Result struct {
	ScanPath     string                 `json:"scan_path"`
	Dependencies []Dependency           `json:"dependencies"`
	Summary      map[string]int         `json:"summary"`             // risk-label → count
	Detectors    []string               `json:"detectors_run"`       // which detectors fired (gomod, npm, etc.)
	Errors       []string               `json:"errors,omitempty"`    // non-fatal errors per detector
}

// NewResult builds an empty Result with an initialised summary map.
func NewResult(scanPath string) *Result {
	return &Result{
		ScanPath: scanPath,
		Summary: map[string]int{
			RiskUnknown.String():        0,
			RiskPermissive.String():     0,
			RiskWeakCopyleft.String():   0,
			RiskStrongCopyleft.String(): 0,
			RiskViral.String():          0,
		},
	}
}

// Add appends a dependency and updates the summary counter.
func (r *Result) Add(dep Dependency) {
	r.Dependencies = append(r.Dependencies, dep)
	r.Summary[dep.PrimaryRisk().String()]++
}

// HasViolations reports whether any dependency carries a risk level
// that policy normally rejects (StrongCopyleft or Viral).
func (r *Result) HasViolations() bool {
	return r.Summary[RiskStrongCopyleft.String()] > 0 || r.Summary[RiskViral.String()] > 0
}
