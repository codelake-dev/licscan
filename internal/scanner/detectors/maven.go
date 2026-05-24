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
	return "maven"
}

// Detect implements scanner.Detector.
func (m *Maven) Detect(rootPath string) (bool, []scanner.Dependency, error) {
	pomPath := filepath.Join(rootPath, "pom.xml")
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
			Ecosystem: "maven",
			Manifest:  "pom.xml",
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

// mapMavenLicenseToSPDX matches Maven's descriptive license-name strings
// against known SPDX identifiers. URL is consulted as a secondary signal
// when the name is ambiguous (e.g. "The Apache License" without version).
//
// Covers the ~15 license names that account for >95% of all Maven Central
// declarations. Unmapped names return "".
func mapMavenLicenseToSPDX(name, url string) string {
	lower := strings.ToLower(name)
	lowerURL := strings.ToLower(url)

	switch {
	case strings.Contains(lower, "apache") && (strings.Contains(lower, "2.0") || strings.Contains(lowerURL, "license-2.0") || strings.Contains(lowerURL, "apache-2.0")):
		return "Apache-2.0"
	case strings.Contains(lower, "apache") && strings.Contains(lower, "1.1"):
		return "Apache-1.1"
	case lower == "the mit license" || lower == "mit license" || lower == "mit":
		return "MIT"
	case strings.Contains(lower, "bsd 3-clause") || strings.Contains(lower, "bsd-3-clause") || strings.Contains(lower, "new bsd"):
		return "BSD-3-Clause"
	case strings.Contains(lower, "bsd 2-clause") || strings.Contains(lower, "bsd-2-clause") || strings.Contains(lower, "simplified bsd"):
		return "BSD-2-Clause"
	case strings.Contains(lower, "bsd"):
		// Generic "BSD License" with no clause count → assume 3-clause
		// (the most common default in Maven Central).
		return "BSD-3-Clause"
	case strings.Contains(lower, "isc"):
		return "ISC"
	case strings.Contains(lower, "eclipse public license") && strings.Contains(lower, "2.0"):
		return "EPL-2.0"
	case strings.Contains(lower, "eclipse public license") && (strings.Contains(lower, "1.0") || lower == "eclipse public license - v 1.0"):
		return "EPL-1.0"
	case strings.Contains(lower, "mozilla public license") && strings.Contains(lower, "2.0"):
		return "MPL-2.0"
	case strings.Contains(lower, "mozilla public license") && strings.Contains(lower, "1.1"):
		return "MPL-1.1"
	case strings.Contains(lower, "common development and distribution") && strings.Contains(lower, "1.1"):
		return "CDDL-1.1"
	case strings.Contains(lower, "common development and distribution"):
		return "CDDL-1.0"
	case strings.Contains(lower, "gnu lesser general public license") && strings.Contains(lower, "2.1"):
		return "LGPL-2.1"
	case strings.Contains(lower, "lgpl") && strings.Contains(lower, "3"):
		return "LGPL-3.0"
	case strings.Contains(lower, "lgpl"):
		return "LGPL-2.1"
	case strings.Contains(lower, "gnu affero") || strings.Contains(lower, "agpl"):
		return "AGPL-3.0"
	case strings.Contains(lower, "gnu general public license") && strings.Contains(lower, "3"):
		return "GPL-3.0"
	case strings.Contains(lower, "gnu general public license") && strings.Contains(lower, "2"):
		return "GPL-2.0"
	case strings.Contains(lower, "gpl") && strings.Contains(lower, "3"):
		return "GPL-3.0"
	case strings.Contains(lower, "gpl") && strings.Contains(lower, "2"):
		return "GPL-2.0"
	case strings.Contains(lower, "creative commons cc0") || lower == "cc0 1.0":
		return "CC0-1.0"
	case strings.Contains(lower, "unlicense"):
		return "Unlicense"
	case strings.Contains(lower, "public domain"):
		return "CC0-1.0"
	}
	return ""
}
