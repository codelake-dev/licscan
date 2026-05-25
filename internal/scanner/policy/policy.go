// Package policy reads .licscan.yml and decides per-dependency verdicts.
//
// Policy file shape (all sections optional):
//
//	deny:
//	  - AGPL-3.0
//	  - SSPL-1.0
//
//	warn:
//	  - GPL-3.0
//	  - LGPL-3.0
//
//	allow_exceptions:
//	  - package: github.com/some/gpl-lib
//	    reason: "only used in tests, never bundled in the production binary"
//
// If no .licscan.yml is present, the default policy denies Strong-Copyleft
// and Viral risk levels, warns on Weak Copyleft, and allows Permissive +
// Unknown (Unknown is surfaced but not treated as a hard violation —
// humans are expected to triage).
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// Verdict labels carried on scanner.Dependency.Verdict after policy runs.
const (
	VerdictAllow  = "allow"
	VerdictWarn   = "warn"
	VerdictDeny   = "deny"
	VerdictExempt = "exempt"
)

// PolicyFile is the on-disk name the engine looks for in the scan root.
const PolicyFile = ".licscan.yml"

// SPDX bases used by Default() — extracted so the `-only` / `-or-later`
// suffixes are computed rather than written as separate literals (keeps
// goconst's substring counter happy).
const (
	spdxAGPL3 = "AGPL-3.0"
	spdxGPL3  = "GPL-3.0"
	spdxGPL2  = "GPL-2.0"
	spdxLGPL3 = "LGPL-3.0"
	spdxLGPL2 = "LGPL-2.1"
)

// Policy is the in-memory representation of .licscan.yml.
type Policy struct {
	Deny            []string     `yaml:"deny"`
	Warn            []string     `yaml:"warn"`
	AllowExceptions []Exception  `yaml:"allow_exceptions"`
	Manufacturer    Manufacturer `yaml:"manufacturer"`
	Product         Product      `yaml:"product"`

	// loadedFromDefault tracks whether this Policy came from the on-disk
	// .licscan.yml (false) or the in-memory Default() (true). Exposed via
	// IsDefault() so callers can show a hint when no policy was found.
	loadedFromDefault bool
}

// Exception names a package that should be exempted regardless of its license.
type Exception struct {
	Package string `yaml:"package"`
	Reason  string `yaml:"reason"`
}

// Manufacturer identifies the producer of the scanned software for EU CRA
// Article 13 evidence. All fields are optional; the CRA exporter degrades
// gracefully (NOASSERTION) for missing values, but a complete block is
// required for regulator submission.
type Manufacturer struct {
	Name    string `yaml:"name"`
	Email   string `yaml:"email"`
	URL     string `yaml:"url"`
	Country string `yaml:"country"`
}

// IsZero reports whether the manufacturer block was left empty in
// .licscan.yml — useful for surfacing a warning when --cra is requested
// without a populated manufacturer.
func (m Manufacturer) IsZero() bool {
	return m.Name == "" && m.Email == "" && m.URL == "" && m.Country == ""
}

// Product identifies the scanned software itself for EU CRA evidence.
// Name typically matches the project / git-repo name; Version may be
// the git tag at scan time. Optional but recommended.
type Product struct {
	Name                string `yaml:"name"`
	Version             string `yaml:"version"`
	Category            string `yaml:"category"`              // CRA risk category if known
	SupportLifecycleEnd string `yaml:"support_lifecycle_end"` // YYYY-MM-DD, default = 5y from release per CRA Art. 13(8)
}

// IsZero reports whether the product block was left empty.
func (p Product) IsZero() bool {
	return p.Name == "" && p.Version == "" && p.Category == "" && p.SupportLifecycleEnd == ""
}

// Default returns the built-in policy applied when .licscan.yml is absent.
//
// Default is intentionally strict-but-not-paranoid:
//   - Strong-Copyleft + Viral licenses are denied (incompatible with closed
//     distribution; explicit policy lets users opt back in for OSS projects)
//   - Weak Copyleft (LGPL, MPL) is warned (legal review recommended but
//     widely shippable with isolation)
//   - Permissive + Unknown are allowed (Unknown is shown but not blocked —
//     humans must triage)
func Default() *Policy {
	const (
		suffixOnly    = "-only"
		suffixOrLater = "-or-later"
	)
	return &Policy{
		Deny: []string{
			spdxGPL2, spdxGPL2 + suffixOnly, spdxGPL2 + suffixOrLater,
			spdxGPL3, spdxGPL3 + suffixOnly, spdxGPL3 + suffixOrLater,
			spdxAGPL3, spdxAGPL3 + suffixOnly, spdxAGPL3 + suffixOrLater,
			"SSPL-1.0",
			"BSL-1.1", "BUSL-1.1",
			"Commons-Clause",
			"Elastic-2.0", "Elastic-License-2.0",
		},
		Warn: []string{
			spdxLGPL2, spdxLGPL2 + suffixOnly, spdxLGPL2 + suffixOrLater,
			spdxLGPL3, spdxLGPL3 + suffixOnly, spdxLGPL3 + suffixOrLater,
			"MPL-1.1", "MPL-2.0",
			"EPL-1.0", "EPL-2.0",
			"CDDL-1.0", "CDDL-1.1",
			"EUPL-1.1", "EUPL-1.2",
		},
		loadedFromDefault: true,
	}
}

// IsDefault reports whether this Policy was returned by Default() (no
// on-disk .licscan.yml was loaded).
func (p *Policy) IsDefault() bool {
	return p.loadedFromDefault
}

// Load reads .licscan.yml from the given directory. Returns Default()
// if the file is not present. Returns a wrapped error if the file
// exists but cannot be parsed.
//
// Field-level inheritance: a .licscan.yml that omits the `deny` or
// `warn` keys entirely inherits the corresponding default list. An
// explicit empty list (e.g. `deny: []`) still means "explicitly allow
// everything in this category" — only the *absence* of the key triggers
// the inherit. This lets a project ship a `.licscan.yml` with just a
// `manufacturer:` block (typical for CRA evidence) without unintentionally
// disabling the deny rules.
func Load(scanRoot string) (*Policy, error) {
	path := filepath.Join(scanRoot, PolicyFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, fmt.Errorf("read %s: %w", PolicyFile, err)
	}

	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", PolicyFile, err)
	}

	// Per-field inherit from defaults when the user omitted the key.
	// nil slice = key absent; non-nil empty slice (e.g. `deny: []`) =
	// explicit override → no inherit.
	defaults := Default()
	if p.Deny == nil {
		p.Deny = defaults.Deny
	}
	if p.Warn == nil {
		p.Warn = defaults.Warn
	}

	return &p, nil
}

// Apply walks every dependency in the result, evaluates the policy
// against it, and sets the per-dependency Verdict + Reason in place.
//
// Order of evaluation:
//  1. If the package is in allow_exceptions → "exempt" (regardless of license)
//  2. If any license is in deny → "deny"
//  3. If any license is in warn → "warn"
//  4. Else → "allow"
func (p *Policy) Apply(result *scanner.Result) {
	if result == nil {
		return
	}

	exceptions := buildExceptionIndex(p.AllowExceptions)
	denySet := buildLicenseSet(p.Deny)
	warnSet := buildLicenseSet(p.Warn)

	for i := range result.Dependencies {
		dep := &result.Dependencies[i]
		if reason, ok := exceptions[dep.Name]; ok {
			dep.Verdict = VerdictExempt
			dep.Reason = reason
			continue
		}
		dep.Verdict, dep.Reason = classify(dep.Licenses, denySet, warnSet)
	}
}

// classify is the per-dep license-set decision (allow / warn / deny).
// "deny" wins over "warn" wins over "allow" when a dep carries multiple licenses.
func classify(licenses []scanner.License, denySet, warnSet map[string]bool) (string, string) {
	denied := ""
	warned := ""
	for _, l := range licenses {
		key := normaliseLicenseKey(l.SPDX)
		if denySet[key] {
			denied = l.SPDX
		} else if warnSet[key] && denied == "" {
			warned = l.SPDX
		}
	}
	switch {
	case denied != "":
		return VerdictDeny, fmt.Sprintf("license %s is in the policy deny list", denied)
	case warned != "":
		return VerdictWarn, fmt.Sprintf("license %s is in the policy warn list", warned)
	default:
		return VerdictAllow, ""
	}
}

// CountByVerdict returns counts of {deny, warn, allow, exempt} across the result.
func CountByVerdict(result *scanner.Result) map[string]int {
	counts := map[string]int{
		VerdictDeny: 0, VerdictWarn: 0, VerdictAllow: 0, VerdictExempt: 0,
	}
	if result == nil {
		return counts
	}
	for _, dep := range result.Dependencies {
		if dep.Verdict != "" {
			counts[dep.Verdict]++
		}
	}
	return counts
}

// HasDenials reports whether any dependency was denied — used by CI mode
// to decide whether to exit non-zero.
func HasDenials(result *scanner.Result) bool {
	return CountByVerdict(result)[VerdictDeny] > 0
}

func buildExceptionIndex(exs []Exception) map[string]string {
	out := make(map[string]string, len(exs))
	for _, e := range exs {
		if e.Package == "" {
			continue
		}
		out[e.Package] = e.Reason
	}
	return out
}

func buildLicenseSet(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		key := normaliseLicenseKey(id)
		if key != "" {
			out[key] = true
		}
	}
	return out
}

func normaliseLicenseKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
