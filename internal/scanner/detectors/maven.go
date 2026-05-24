package detectors

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// Maven is the detector for Java projects (pom.xml).
//
// V1 scope: parses <dependencies> in the project's pom.xml. Does NOT
// expand <dependencyManagement>, parent POMs, property substitution
// (${...}), profiles, or transitive resolution — that requires a full
// Maven execution. Customers who need transitive coverage can run
// `mvn dependency:tree` first and point licscan at the result, or
// rely on the V2 maven-cache walker (planned).
//
// License resolution: M2Resolver inspects ~/.m2/repository/<groupId-path>/
// <artifactId>/<version>/<artifactId>-<version>.pom for <licenses><license>
// <name>.
type Maven struct {
	Resolver MavenResolver
}

// MavenResolver looks up the license for a Maven coordinate.
type MavenResolver interface {
	Resolve(groupID, artifactID, version string) (spdx string, source string)
}

// Name implements scanner.Detector.
func (m *Maven) Name() string {
	return ecosystemMaven
}

// Detect implements scanner.Detector.
func (m *Maven) Detect(rootPath string) (bool, []scanner.Dependency, error) {
	pomPath := filepath.Join(rootPath, manifestPomXML)
	raw, err := os.ReadFile(pomPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("read pom.xml: %w", err)
	}

	var pom mavenPOM
	if err := xml.Unmarshal(raw, &pom); err != nil {
		return true, nil, fmt.Errorf("parse pom.xml: %w", err)
	}

	resolver := m.Resolver
	if resolver == nil {
		resolver = NewM2Resolver()
	}

	deps := make([]scanner.Dependency, 0, len(pom.Dependencies.Dependency))
	for _, d := range pom.Dependencies.Dependency {
		if d.GroupID == "" || d.ArtifactID == "" {
			continue
		}
		coord := d.GroupID + ":" + d.ArtifactID
		dep := scanner.Dependency{
			Name:      coord,
			Version:   d.Version,
			Ecosystem: ecosystemMaven,
			Manifest:  manifestPomXML,
			Direct:    true, // V1: every entry in pom.xml is direct
		}

		spdx, source := resolver.Resolve(d.GroupID, d.ArtifactID, d.Version)
		if spdx == "" {
			dep.Licenses = []scanner.License{scanner.NewLicense("Unknown", "")}
			dep.Notes = append(dep.Notes,
				"license not found in ~/.m2/repository — run `mvn dependency:resolve` first; transitive deps require `mvn dependency:tree` (V1 limitation)")
		} else {
			dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
		}
		deps = append(deps, dep)
	}
	return true, deps, nil
}

// ── pom.xml schema (subset) ────────────────────────────────────

type mavenPOM struct {
	XMLName      xml.Name          `xml:"project"`
	GroupID      string            `xml:"groupId"`
	ArtifactID   string            `xml:"artifactId"`
	Version      string            `xml:"version"`
	Licenses     mavenLicensesNode `xml:"licenses"`
	Dependencies mavenDepsNode     `xml:"dependencies"`
}

type mavenLicensesNode struct {
	License []mavenLicense `xml:"license"`
}

type mavenLicense struct {
	Name string `xml:"name"`
	URL  string `xml:"url"`
}

type mavenDepsNode struct {
	Dependency []mavenDependency `xml:"dependency"`
}

type mavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// ── M2Resolver ─────────────────────────────────────────────────

// M2Resolver inspects ~/.m2/repository for the .pom of each dep,
// extracts <licenses><license><name>, and maps the descriptive name
// to an SPDX identifier.
type M2Resolver struct {
	RepoRoot string // override for tests
}

// NewM2Resolver builds a resolver pointing at ~/.m2/repository (or
// $MAVEN_REPO if set).
func NewM2Resolver() *M2Resolver {
	return &M2Resolver{RepoRoot: defaultM2Repo()}
}

func defaultM2Repo() string {
	if r := os.Getenv("MAVEN_REPO"); r != "" {
		return r
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".m2", "repository")
	}
	return ""
}

// Resolve implements MavenResolver.
func (r *M2Resolver) Resolve(groupID, artifactID, version string) (string, string) {
	if r.RepoRoot == "" || groupID == "" || artifactID == "" || version == "" {
		return "", ""
	}
	groupPath := strings.ReplaceAll(groupID, ".", string(filepath.Separator))
	pomPath := filepath.Join(r.RepoRoot, groupPath, artifactID, version, artifactID+"-"+version+".pom")

	data, err := os.ReadFile(pomPath)
	if err != nil {
		return "", ""
	}

	var pom mavenPOM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return "", pomPath
	}

	for _, lic := range pom.Licenses.License {
		if spdx := mapMavenLicenseToSPDX(lic.Name, lic.URL); spdx != "" {
			return spdx, pomPath
		}
	}
	return "", pomPath
}

// mavenLicensePattern is one entry in the descriptive-name → SPDX
// mapping table. `must` substrings are checked against the lowercased
// license name (and optionally the URL); the first matching entry wins.
type mavenLicensePattern struct {
	spdx      string
	nameAll   []string // every substring must appear in the name
	nameOrURL []string // any one of these substrings must appear in either name or URL
	exactName []string // license name (already lowercased) matches one of these exactly
}

// mavenLicensePatterns is evaluated in order. More specific patterns
// must come first (e.g. AGPL before GPL, LGPL-2.1 before LGPL, EPL-2.0
// before EPL-1.0, "BSD 3-Clause" before generic "BSD").
//
// Covers the license names that account for >95% of all Maven Central
// declarations. Unmapped names return "".
var mavenLicensePatterns = []mavenLicensePattern{
	// Apache
	{spdx: spdxApache20, nameAll: []string{"apache"}, nameOrURL: []string{"2.0", "license-2.0", "apache-2.0"}},
	{spdx: "Apache-1.1", nameAll: []string{"apache", "1.1"}},

	// MIT (exact-match only — "MIT" is too short to substring-match safely)
	{spdx: "MIT", exactName: []string{"the mit license", "mit license", "mit"}},

	// BSD — specific clause-counts first, then generic fallback
	{spdx: spdxBSD3Clause, nameAll: []string{"bsd 3-clause"}},
	{spdx: spdxBSD3Clause, nameAll: []string{"bsd-3-clause"}},
	{spdx: spdxBSD3Clause, nameAll: []string{"new bsd"}},
	{spdx: "BSD-2-Clause", nameAll: []string{"bsd 2-clause"}},
	{spdx: "BSD-2-Clause", nameAll: []string{"bsd-2-clause"}},
	{spdx: "BSD-2-Clause", nameAll: []string{"simplified bsd"}},
	{spdx: spdxBSD3Clause, nameAll: []string{"bsd"}}, // generic "BSD License" → 3-clause (Maven Central default)

	// ISC
	{spdx: "ISC", nameAll: []string{"isc"}},

	// Eclipse Public License
	{spdx: "EPL-2.0", nameAll: []string{"eclipse public license", "2.0"}},
	{spdx: "EPL-1.0", nameAll: []string{"eclipse public license", "1.0"}},
	{spdx: "EPL-1.0", exactName: []string{"eclipse public license - v 1.0"}},

	// Mozilla Public License
	{spdx: "MPL-2.0", nameAll: []string{"mozilla public license", "2.0"}},
	{spdx: "MPL-1.1", nameAll: []string{"mozilla public license", "1.1"}},

	// CDDL — 1.1 before 1.0 fallback
	{spdx: "CDDL-1.1", nameAll: []string{"common development and distribution", "1.1"}},
	{spdx: "CDDL-1.0", nameAll: []string{"common development and distribution"}},

	// LGPL — full GNU phrasing first, then short forms
	{spdx: spdxLGPL21, nameAll: []string{"gnu lesser general public license", "2.1"}},
	{spdx: "LGPL-3.0", nameAll: []string{"lgpl", "3"}},
	{spdx: spdxLGPL21, nameAll: []string{"lgpl"}},

	// AGPL must precede GPL (substring) — same trick as the SPDX matcher
	{spdx: "AGPL-3.0", nameAll: []string{"gnu affero"}},
	{spdx: "AGPL-3.0", nameAll: []string{"agpl"}},

	// GPL — full phrasing first, then short forms
	{spdx: spdxGPL30, nameAll: []string{"gnu general public license", "3"}},
	{spdx: spdxGPL20, nameAll: []string{"gnu general public license", "2"}},
	{spdx: spdxGPL30, nameAll: []string{"gpl", "3"}},
	{spdx: spdxGPL20, nameAll: []string{"gpl", "2"}},

	// Public-domain dedications
	{spdx: spdxCC010, nameAll: []string{"creative commons cc0"}},
	{spdx: spdxCC010, exactName: []string{"cc0 1.0"}},
	{spdx: "Unlicense", nameAll: []string{"unlicense"}},
	{spdx: spdxCC010, nameAll: []string{"public domain"}},
}

// mapMavenLicenseToSPDX matches Maven's descriptive license-name strings
// against known SPDX identifiers. URL is consulted as a secondary signal
// when the name is ambiguous (e.g. "The Apache License" without version).
func mapMavenLicenseToSPDX(name, url string) string {
	lower := strings.ToLower(name)
	lowerURL := strings.ToLower(url)

	for _, p := range mavenLicensePatterns {
		if p.matches(lower, lowerURL) {
			return p.spdx
		}
	}
	return ""
}

func (p mavenLicensePattern) matches(lowerName, lowerURL string) bool {
	for _, e := range p.exactName {
		if lowerName == e {
			return true
		}
	}
	if len(p.nameAll) > 0 {
		for _, s := range p.nameAll {
			if !strings.Contains(lowerName, s) {
				return false
			}
		}
		if len(p.nameOrURL) == 0 {
			return true
		}
		for _, s := range p.nameOrURL {
			if strings.Contains(lowerName, s) || strings.Contains(lowerURL, s) {
				return true
			}
		}
		return false
	}
	return false
}
