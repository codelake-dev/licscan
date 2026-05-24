package detectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// Npm is the detector for Node.js projects (package.json + package-lock.json).
//
// It handles three lockfile generations:
//   - v1 (npm 5-6): nested `dependencies` tree, license must be resolved from node_modules
//   - v2 (npm 7):   both `dependencies` (compat) and `packages` (flat); we prefer `packages`
//   - v3 (npm 8+):  only `packages`; license is typically inlined
//
// If package-lock.json is missing, only the direct deps from package.json
// are reported (with a Note explaining transitive coverage is incomplete).
type Npm struct {
	Resolver NpmResolver
}

// NpmResolver looks up a license for an npm package by name+version.
type NpmResolver interface {
	Resolve(name, version string) (spdx string, source string)
}

// Name implements scanner.Detector.
func (n *Npm) Name() string {
	return "npm"
}

// Detect implements scanner.Detector.
func (n *Npm) Detect(rootPath string) (bool, []scanner.Dependency, error) {
	pkgPath := filepath.Join(rootPath, "package.json")
	pkgRaw, err := os.ReadFile(pkgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("read package.json: %w", err)
	}

	var pkg packageJSON
	if err := json.Unmarshal(pkgRaw, &pkg); err != nil {
		return true, nil, fmt.Errorf("parse package.json: %w", err)
	}

	resolver := n.Resolver
	if resolver == nil {
		resolver = &NodeModulesResolver{NodeModulesDir: filepath.Join(rootPath, "node_modules")}
	}

	directNames := pkg.directDependencyNames()

	// Prefer package-lock.json for complete (direct + transitive) coverage.
	lockPath := filepath.Join(rootPath, "package-lock.json")
	if lockRaw, lockErr := os.ReadFile(lockPath); lockErr == nil {
		deps, parseErr := parseLockfile(lockRaw, directNames, resolver)
		if parseErr != nil {
			return true, nil, fmt.Errorf("parse package-lock.json: %w", parseErr)
		}
		return true, deps, nil
	}

	// No lock file — fall back to direct deps only.
	deps := make([]scanner.Dependency, 0, len(pkg.Dependencies)+len(pkg.DevDependencies))
	for name, version := range pkg.allDependencies() {
		dep := newNpmDependency(name, version, true, resolver)
		dep.Notes = append(dep.Notes,
			"package-lock.json missing — transitive dependencies were not analysed")
		deps = append(deps, dep)
	}
	return true, deps, nil
}

// ── package.json types ─────────────────────────────────────────

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	License              json.RawMessage   `json:"license,omitempty"`
	Licenses             json.RawMessage   `json:"licenses,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
}

// directDependencyNames returns a set of every name listed as a direct
// dep across all four dependency buckets. Used to mark packages as direct
// when walking the lockfile.
func (p packageJSON) directDependencyNames() map[string]bool {
	out := make(map[string]bool, len(p.Dependencies))
	for _, group := range []map[string]string{
		p.Dependencies, p.DevDependencies, p.PeerDependencies, p.OptionalDependencies,
	} {
		for name := range group {
			out[name] = true
		}
	}
	return out
}

func (p packageJSON) allDependencies() map[string]string {
	out := make(map[string]string)
	for _, group := range []map[string]string{
		p.Dependencies, p.DevDependencies, p.PeerDependencies, p.OptionalDependencies,
	} {
		for name, version := range group {
			out[name] = version
		}
	}
	return out
}

// ── package-lock.json parsing ──────────────────────────────────

type lockfile struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]lockfilePackage `json:"packages,omitempty"`        // v2/v3
	Dependencies    map[string]lockfileDepV1   `json:"dependencies,omitempty"`    // v1 + v2 compat
}

type lockfilePackage struct {
	Version  string          `json:"version"`
	License  json.RawMessage `json:"license,omitempty"`
	Licenses json.RawMessage `json:"licenses,omitempty"`
	Dev      bool            `json:"dev,omitempty"`
}

type lockfileDepV1 struct {
	Version      string                  `json:"version"`
	Dev          bool                    `json:"dev,omitempty"`
	Dependencies map[string]lockfileDepV1 `json:"dependencies,omitempty"` // nested
}

func parseLockfile(raw []byte, directNames map[string]bool, resolver NpmResolver) ([]scanner.Dependency, error) {
	var lock lockfile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	// v2/v3 — prefer `packages` if present (inline license, flat structure).
	if len(lock.Packages) > 0 {
		return parsePackagesMap(lock.Packages, directNames, resolver), nil
	}

	// v1 — walk nested `dependencies` tree, resolver provides licenses.
	if len(lock.Dependencies) > 0 {
		return parseDependenciesTreeV1(lock.Dependencies, directNames, resolver), nil
	}

	return nil, nil
}

func parsePackagesMap(packages map[string]lockfilePackage, directNames map[string]bool, resolver NpmResolver) []scanner.Dependency {
	deps := make([]scanner.Dependency, 0, len(packages))
	for key, pkg := range packages {
		// The empty key represents the project itself — skip.
		if key == "" {
			continue
		}
		name := nameFromLockfileKey(key)
		if name == "" {
			continue
		}

		dep := scanner.Dependency{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: "npm",
			Manifest:  "package-lock.json",
			Direct:    directNames[name],
		}

		// Try inline license first (v2/v3 typically inline it).
		spdx := extractLicenseFromRawMessage(pkg.License)
		if spdx == "" {
			spdx = extractLicenseFromRawMessage(pkg.Licenses)
		}
		source := "package-lock.json"

		if spdx == "" && resolver != nil {
			spdx, source = resolver.Resolve(name, pkg.Version)
		}

		if spdx == "" {
			dep.Licenses = []scanner.License{scanner.NewLicense("Unknown", "")}
			dep.Notes = append(dep.Notes,
				"license not declared in package-lock.json and not found in node_modules")
		} else {
			dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
		}
		deps = append(deps, dep)
	}
	return deps
}

func parseDependenciesTreeV1(tree map[string]lockfileDepV1, directNames map[string]bool, resolver NpmResolver) []scanner.Dependency {
	var deps []scanner.Dependency
	var walk func(map[string]lockfileDepV1, bool)
	walk = func(level map[string]lockfileDepV1, atTopLevel bool) {
		for name, info := range level {
			direct := atTopLevel && directNames[name]
			dep := newNpmDependency(name, info.Version, direct, resolver)
			deps = append(deps, dep)
			if len(info.Dependencies) > 0 {
				walk(info.Dependencies, false)
			}
		}
	}
	walk(tree, true)
	return deps
}

// nameFromLockfileKey converts a v2/v3 lockfile key (e.g.
// "node_modules/lodash" or "node_modules/@babel/core") to the package
// name. Nested node_modules paths (deduplication artefacts) are mapped
// to the leaf package name.
func nameFromLockfileKey(key string) string {
	parts := strings.Split(key, "node_modules/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

// ── License-field extraction (handles 4 shapes) ─────────────────

// extractLicenseFromRawMessage extracts an SPDX ID from a package.json
// `license` / `licenses` value, supporting:
//   - string:   "MIT"            → "MIT"
//   - string:   "(MIT OR Apache-2.0)" → "MIT" (first identifier)
//   - object:   {"type":"MIT"}   → "MIT"
//   - array:    [{"type":"MIT"}, {"type":"Apache-2.0"}] → "MIT" (first)
//   - "SEE LICENSE IN file"      → "" (caller must scan LICENSE file)
//   - "UNLICENSED"               → "UNLICENSED" (no SPDX classification)
func extractLicenseFromRawMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return cleanLicenseString(s)
	}

	// Try object {type: "..."}.
	var obj struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.Type != "" {
		return cleanLicenseString(obj.Type)
	}

	// Try array [{type: "..."}].
	var arr []struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 && arr[0].Type != "" {
		return cleanLicenseString(arr[0].Type)
	}

	return ""
}

func cleanLicenseString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(s), "SEE LICENSE") {
		// indirection — let resolver fall back to LICENSE file scan
		return ""
	}
	// Take first identifier from SPDX expressions like "(MIT OR Apache-2.0)".
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	if idx := strings.IndexAny(s, " "); idx > 0 {
		s = s[:idx]
	}
	return s
}

// ── Dependency construction ────────────────────────────────────

func newNpmDependency(name, version string, direct bool, resolver NpmResolver) scanner.Dependency {
	dep := scanner.Dependency{
		Name:      name,
		Version:   version,
		Ecosystem: "npm",
		Manifest:  "package.json",
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
			"license could not be resolved from node_modules — run `npm install` first")
	} else {
		dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
	}
	return dep
}

// ── NodeModulesResolver ────────────────────────────────────────

// NodeModulesResolver inspects node_modules/<name>/package.json for the
// license field, falling back to LICENSE-files when the field is absent.
type NodeModulesResolver struct {
	NodeModulesDir string
}

// Resolve implements NpmResolver.
func (r *NodeModulesResolver) Resolve(name, _ string) (string, string) {
	if r.NodeModulesDir == "" || name == "" {
		return "", ""
	}
	pkgDir := filepath.Join(r.NodeModulesDir, name)
	pkgJSON := filepath.Join(pkgDir, "package.json")

	if data, err := os.ReadFile(pkgJSON); err == nil {
		var p packageJSON
		if json.Unmarshal(data, &p) == nil {
			if spdx := extractLicenseFromRawMessage(p.License); spdx != "" {
				return spdx, pkgJSON
			}
			if spdx := extractLicenseFromRawMessage(p.Licenses); spdx != "" {
				return spdx, pkgJSON
			}
		}
	}

	// Fall back to LICENSE-file scan.
	for _, fname := range LicenseFileNames {
		path := filepath.Join(pkgDir, fname)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if spdx := scanner.IdentifyLicense(string(data)); spdx != "" {
			return spdx, path
		}
		return "", path
	}
	return "", ""
}
