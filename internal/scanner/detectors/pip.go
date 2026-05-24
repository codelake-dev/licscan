package detectors

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// Pip is the detector for Python projects.
//
// Python has many competing manifest formats; we try them in order of
// information richness:
//   1. poetry.lock      — TOML, full transitive list
//   2. Pipfile.lock     — JSON (pipenv), full transitive list (default+develop)
//   3. requirements.txt — flat list, direct deps only
//   4. pyproject.toml   — PEP 621 [project.dependencies], direct deps only
//
// Whichever is found first wins. None of these formats carry license
// info inline, so resolution always goes through the resolver — which
// reads <site-packages>/<dist>-<ver>.dist-info/METADATA for the `License:`
// header (or `Classifier: License :: OSI Approved :: ...`).
type Pip struct {
	Resolver PipResolver
}

// PipResolver looks up the license for a Python distribution by name+version.
type PipResolver interface {
	Resolve(name, version string) (spdx string, source string)
}

// Name implements scanner.Detector.
func (p *Pip) Name() string {
	return "pip"
}

// Detect implements scanner.Detector.
func (p *Pip) Detect(rootPath string) (bool, []scanner.Dependency, error) {
	resolver := p.Resolver
	if resolver == nil {
		resolver = NewSitePackagesResolver(rootPath)
	}

	// Try lockfiles first — they have full transitive coverage.
	if raw, err := os.ReadFile(filepath.Join(rootPath, "poetry.lock")); err == nil {
		deps, perr := parsePoetryLock(raw, rootPath, resolver)
		if perr != nil {
			return true, nil, fmt.Errorf("parse poetry.lock: %w", perr)
		}
		return true, deps, nil
	}
	if raw, err := os.ReadFile(filepath.Join(rootPath, "Pipfile.lock")); err == nil {
		deps, perr := parsePipfileLock(raw, resolver)
		if perr != nil {
			return true, nil, fmt.Errorf("parse Pipfile.lock: %w", perr)
		}
		return true, deps, nil
	}

	// Fall back to direct-only sources.
	directs := map[string]string{}
	foundAny := false

	if raw, err := os.ReadFile(filepath.Join(rootPath, "requirements.txt")); err == nil {
		foundAny = true
		for name, version := range parseRequirementsTxt(raw) {
			directs[name] = version
		}
	}
	if raw, err := os.ReadFile(filepath.Join(rootPath, "pyproject.toml")); err == nil {
		foundAny = true
		for name, version := range parsePyprojectTOML(raw) {
			if _, exists := directs[name]; !exists {
				directs[name] = version
			}
		}
	}

	if !foundAny {
		return false, nil, nil
	}

	deps := make([]scanner.Dependency, 0, len(directs))
	for name, version := range directs {
		dep := newPipDependency(name, version, true, "requirements.txt", resolver)
		dep.Notes = append(dep.Notes,
			"no lockfile present — transitive dependencies were not analysed")
		deps = append(deps, dep)
	}
	return true, deps, nil
}

// ── poetry.lock parsing ────────────────────────────────────────

type poetryLockfile struct {
	Packages []poetryLockPackage `toml:"package"`
}

type poetryLockPackage struct {
	Name     string `toml:"name"`
	Version  string `toml:"version"`
	Optional bool   `toml:"optional"`
	Category string `toml:"category"` // only present in older poetry; "main"=runtime, "dev"=dev
}

func parsePoetryLock(raw []byte, rootPath string, resolver PipResolver) ([]scanner.Dependency, error) {
	var lock poetryLockfile
	if err := toml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	// Direct deps come from pyproject.toml (the project file). Read it
	// alongside so we can correctly mark direct-vs-transitive — without
	// it we'd flag everything as transitive.
	directSet := map[string]bool{}
	if rootPath != "" {
		if data, err := os.ReadFile(filepath.Join(rootPath, "pyproject.toml")); err == nil {
			for name := range parsePyprojectTOML(data) {
				directSet[normalisePyName(name)] = true
			}
		}
	}

	deps := make([]scanner.Dependency, 0, len(lock.Packages))
	for _, pkg := range lock.Packages {
		dep := newPipDependency(pkg.Name, pkg.Version, directSet[normalisePyName(pkg.Name)],
			"poetry.lock", resolver)
		deps = append(deps, dep)
	}
	return deps, nil
}

// ── Pipfile.lock parsing ───────────────────────────────────────

type pipfileLockfile struct {
	Default map[string]pipfileLockEntry `json:"default"`
	Develop map[string]pipfileLockEntry `json:"develop"`
}

type pipfileLockEntry struct {
	Version string `json:"version"` // "==1.2.3"
}

func parsePipfileLock(raw []byte, resolver PipResolver) ([]scanner.Dependency, error) {
	var lock pipfileLockfile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	deps := make([]scanner.Dependency, 0, len(lock.Default)+len(lock.Develop))
	for name, entry := range lock.Default {
		deps = append(deps, newPipDependency(name, strings.TrimPrefix(entry.Version, "=="),
			true, "Pipfile.lock", resolver))
	}
	for name, entry := range lock.Develop {
		deps = append(deps, newPipDependency(name, strings.TrimPrefix(entry.Version, "=="),
			true, "Pipfile.lock", resolver))
	}
	return deps, nil
}

// ── requirements.txt parsing ───────────────────────────────────

var requirementRegex = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*([=~<>!]*)\s*([0-9A-Za-z.\-_]*)`)

// parseRequirementsTxt returns name → version map. Pins are extracted
// where present; otherwise version is empty (caller treats as unknown).
// Comments, -r/-e/-f/--index-url options, and URLs are skipped.
func parseRequirementsTxt(raw []byte) map[string]string {
	out := map[string]string{}
	scn := bufio.NewScanner(strings.NewReader(string(raw)))
	for scn.Scan() {
		line := strings.TrimSpace(scn.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "--") {
			continue // -r requirements-dev.txt, -e ., --index-url, etc.
		}
		if strings.Contains(line, "://") {
			continue // direct URL spec, no canonical name
		}
		// Strip end-of-line comments
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		m := requirementRegex.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		version := ""
		if m[2] == "==" {
			version = m[3]
		}
		out[name] = version
	}
	return out
}

// ── pyproject.toml parsing ─────────────────────────────────────

type pyprojectTOML struct {
	Project struct {
		Dependencies []string `toml:"dependencies"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Dependencies map[string]toml.Primitive `toml:"dependencies"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

func parsePyprojectTOML(raw []byte) map[string]string {
	out := map[string]string{}
	var p pyprojectTOML
	if err := toml.Unmarshal(raw, &p); err != nil {
		return out
	}

	// PEP 621 — [project] dependencies = ["django>=4.2", "psycopg2-binary"]
	for _, spec := range p.Project.Dependencies {
		if m := requirementRegex.FindStringSubmatch(spec); m != nil {
			ver := ""
			if m[2] == "==" {
				ver = m[3]
			}
			out[m[1]] = ver
		}
	}

	// Poetry — [tool.poetry.dependencies] (mapping). Drop the magic
	// `python` entry which is the Python-version constraint, not a package.
	for name := range p.Tool.Poetry.Dependencies {
		if name == "python" {
			continue
		}
		if _, exists := out[name]; !exists {
			out[name] = ""
		}
	}
	return out
}

// ── Dependency construction ────────────────────────────────────

func newPipDependency(name, version string, direct bool, manifest string, resolver PipResolver) scanner.Dependency {
	dep := scanner.Dependency{
		Name:      name,
		Version:   version,
		Ecosystem: "pip",
		Manifest:  manifest,
		Direct:    direct,
	}
	spdx := ""
	source := ""
	if resolver != nil {
		spdx, source = resolver.Resolve(name, version)
	}
	if spdx == "" {
		dep.Licenses = []scanner.License{scanner.NewLicense("Unknown", "")}
		dep.Notes = append(dep.Notes,
			"license could not be resolved from site-packages — install the project first (pip / poetry / pipenv)")
	} else {
		dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
	}
	return dep
}

// normalisePyName matches Python's PEP 503 normalisation: lowercase,
// runs of -_. collapsed to a single -. Required because pyproject.toml
// might say "Pillow" while poetry.lock says "pillow".
func normalisePyName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	prevDash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	return b.String()
}

// ── SitePackagesResolver ───────────────────────────────────────

// SitePackagesResolver inspects <project>/.venv/lib/python*/site-packages/
// <dist>-<ver>.dist-info/METADATA for the License: header. If the project
// doesn't ship a venv, no resolution happens (V1 scope).
type SitePackagesResolver struct {
	ProjectRoot string
}

// NewSitePackagesResolver returns a resolver wired to the project's local venv.
func NewSitePackagesResolver(projectRoot string) *SitePackagesResolver {
	return &SitePackagesResolver{ProjectRoot: projectRoot}
}

// Resolve implements PipResolver.
func (r *SitePackagesResolver) Resolve(name, version string) (string, string) {
	if r.ProjectRoot == "" || name == "" {
		return "", ""
	}

	siteDirs := r.candidateSitePackages()
	for _, site := range siteDirs {
		if spdx, source := lookupDistInfo(site, name, version); spdx != "" || source != "" {
			return spdx, source
		}
	}
	return "", ""
}

func (r *SitePackagesResolver) candidateSitePackages() []string {
	var out []string
	for _, venvName := range []string{".venv", "venv", "env"} {
		venvLib := filepath.Join(r.ProjectRoot, venvName, "lib")
		entries, err := os.ReadDir(venvLib)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "python") {
				out = append(out, filepath.Join(venvLib, e.Name(), "site-packages"))
			}
		}
	}
	return out
}

// lookupDistInfo searches site-packages for <name>-<version>.dist-info/METADATA
// (PEP 376). If version is empty, takes any matching .dist-info dir.
func lookupDistInfo(siteDir, name, version string) (string, string) {
	normName := strings.ReplaceAll(normalisePyName(name), "-", "_")

	entries, err := os.ReadDir(siteDir)
	if err != nil {
		return "", ""
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".dist-info") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".dist-info")
		// "django-4.2.7" or "Django-4.2.7"
		idx := strings.LastIndex(base, "-")
		if idx < 0 {
			continue
		}
		entryName := normalisePyName(base[:idx])
		entryName = strings.ReplaceAll(entryName, "-", "_")
		entryVer := base[idx+1:]

		if entryName != normName {
			continue
		}
		if version != "" && entryVer != version {
			continue
		}

		metaPath := filepath.Join(siteDir, e.Name(), "METADATA")
		if data, err := os.ReadFile(metaPath); err == nil {
			if spdx := extractLicenseFromPEP621Metadata(data); spdx != "" {
				return spdx, metaPath
			}
			return "", metaPath
		}
		break
	}
	return "", ""
}

// extractLicenseFromPEP621Metadata parses the RFC 822-style headers in
// dist-info/METADATA looking for `License:` or `License-Expression:`,
// then falls back to Classifier mining.
func extractLicenseFromPEP621Metadata(data []byte) string {
	text := string(data)
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "License-Expression:"):
			val := strings.TrimSpace(strings.TrimPrefix(line, "License-Expression:"))
			if val != "" && val != "UNKNOWN" {
				return cleanLicenseString(val)
			}
		case strings.HasPrefix(line, "License:"):
			val := strings.TrimSpace(strings.TrimPrefix(line, "License:"))
			if val != "" && val != "UNKNOWN" {
				return cleanLicenseString(val)
			}
		case strings.HasPrefix(line, "Classifier: License ::"):
			// "Classifier: License :: OSI Approved :: MIT License"
			//                                            ^^^^^^^^^^^^
			if spdx := mapClassifierToSPDX(line); spdx != "" {
				return spdx
			}
		}
	}
	return ""
}

// mapClassifierToSPDX maps a trove-classifier to the closest SPDX ID.
// Covers the most common cases; the long tail returns "".
func mapClassifierToSPDX(line string) string {
	switch {
	case strings.Contains(line, "MIT License"):
		return "MIT"
	case strings.Contains(line, "Apache Software License"):
		return "Apache-2.0"
	case strings.Contains(line, "BSD License"):
		return "BSD-3-Clause"
	case strings.Contains(line, "ISC License (ISCL)"):
		return "ISC"
	case strings.Contains(line, "GNU General Public License v3 (GPLv3)"):
		return "GPL-3.0"
	case strings.Contains(line, "GNU General Public License v2 (GPLv2)"):
		return "GPL-2.0"
	case strings.Contains(line, "GNU Lesser General Public License v3 (LGPLv3)"):
		return "LGPL-3.0"
	case strings.Contains(line, "GNU Lesser General Public License v2 (LGPLv2)"):
		return "LGPL-2.1"
	case strings.Contains(line, "GNU Affero General Public License v3 (AGPLv3)"):
		return "AGPL-3.0"
	case strings.Contains(line, "Mozilla Public License 2.0 (MPL 2.0)"):
		return "MPL-2.0"
	case strings.Contains(line, "Python Software Foundation License"):
		return "Python-2.0"
	}
	return ""
}
