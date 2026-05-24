package detectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// Composer is the detector for PHP projects (composer.json + composer.lock).
//
// composer.lock is preferred — it pins exact versions for both runtime
// (`packages`) and dev (`packages-dev`) deps with inline license info.
// Without a lockfile we fall back to composer.json's `require` + `require-dev`
// and try to resolve licenses from vendor/<vendor>/<pkg>/composer.json.
type Composer struct {
	Resolver ComposerResolver
}

// ComposerResolver looks up a license for a Composer package by name.
// Version is unused for now (vendor/ only stores one version at a time).
type ComposerResolver interface {
	Resolve(name, version string) (spdx string, source string)
}

// Name implements scanner.Detector.
func (c *Composer) Name() string {
	return ecosystemComposer
}

// Detect implements scanner.Detector.
func (c *Composer) Detect(rootPath string) (bool, []scanner.Dependency, error) {
	composerJSONPath := filepath.Join(rootPath, manifestComposerJSON)
	rawJSON, err := os.ReadFile(composerJSONPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("read composer.json: %w", err)
	}

	var manifest composerManifest
	if err := json.Unmarshal(rawJSON, &manifest); err != nil {
		return true, nil, fmt.Errorf("parse composer.json: %w", err)
	}

	resolver := c.Resolver
	if resolver == nil {
		resolver = &VendorResolver{VendorDir: filepath.Join(rootPath, "vendor")}
	}

	directNames := manifest.directNames()

	// Prefer composer.lock for complete (direct + transitive) coverage.
	lockPath := filepath.Join(rootPath, manifestComposerLock)
	if rawLock, lockErr := os.ReadFile(lockPath); lockErr == nil {
		var lock composerLock
		if err := json.Unmarshal(rawLock, &lock); err != nil {
			return true, nil, fmt.Errorf("parse composer.lock: %w", err)
		}
		return true, composerDepsFromLock(lock, directNames, resolver), nil
	}

	// No lock file — fall back to direct deps.
	deps := make([]scanner.Dependency, 0, len(manifest.Require)+len(manifest.RequireDev))
	for name, version := range manifest.allDirectRequires() {
		dep := newComposerDependency(name, version, true, resolver)
		dep.Notes = append(dep.Notes,
			"composer.lock missing — transitive dependencies were not analysed")
		deps = append(deps, dep)
	}
	return true, deps, nil
}

// ── composer.json types ────────────────────────────────────────

type composerManifest struct {
	Require    map[string]string `json:"require,omitempty"`
	RequireDev map[string]string `json:"require-dev,omitempty"`
}

func (m composerManifest) directNames() map[string]bool {
	out := make(map[string]bool, len(m.Require)+len(m.RequireDev))
	for name := range m.Require {
		out[name] = true
	}
	for name := range m.RequireDev {
		out[name] = true
	}
	return out
}

func (m composerManifest) allDirectRequires() map[string]string {
	out := make(map[string]string)
	for name, version := range m.Require {
		// Skip platform requirements (php, ext-*, lib-*) — they're not packages.
		if name == "php" || len(name) > 4 && (name[:4] == "ext-" || name[:4] == "lib-") {
			continue
		}
		out[name] = version
	}
	for name, version := range m.RequireDev {
		if name == "php" || len(name) > 4 && (name[:4] == "ext-" || name[:4] == "lib-") {
			continue
		}
		out[name] = version
	}
	return out
}

// ── composer.lock types ────────────────────────────────────────

type composerLock struct {
	Packages    []composerLockPackage `json:"packages"`
	PackagesDev []composerLockPackage `json:"packages-dev"`
}

type composerLockPackage struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	License []string `json:"license"`
}

func composerDepsFromLock(lock composerLock, directNames map[string]bool, resolver ComposerResolver) []scanner.Dependency {
	all := make([]composerLockPackage, 0, len(lock.Packages)+len(lock.PackagesDev))
	all = append(all, lock.Packages...)
	all = append(all, lock.PackagesDev...)

	deps := make([]scanner.Dependency, 0, len(all))
	for _, pkg := range all {
		dep := scanner.Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: ecosystemComposer,
			Manifest:  manifestComposerLock,
			Direct:    directNames[pkg.Name],
		}

		spdx := firstNonEmpty(pkg.License)
		source := manifestComposerLock
		if spdx == "" && resolver != nil {
			spdx, source = resolver.Resolve(pkg.Name, pkg.Version)
		}

		if spdx == "" {
			dep.Licenses = []scanner.License{scanner.NewLicense("Unknown", "")}
			dep.Notes = append(dep.Notes,
				"license not declared in composer.lock and not found in vendor/")
		} else {
			dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
		}
		deps = append(deps, dep)
	}
	return deps
}

func firstNonEmpty(items []string) string {
	for _, s := range items {
		if s != "" {
			return s
		}
	}
	return ""
}

// ── Dependency construction ────────────────────────────────────

func newComposerDependency(name, version string, direct bool, resolver ComposerResolver) scanner.Dependency {
	dep := scanner.Dependency{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystemComposer,
		Manifest:  manifestComposerJSON,
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
			"license could not be resolved from vendor/ — run `composer install` first")
	} else {
		dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
	}
	return dep
}

// ── VendorResolver ─────────────────────────────────────────────

// VendorResolver inspects vendor/<vendor>/<pkg>/composer.json for the
// license field, falling back to LICENSE-files when the field is absent.
type VendorResolver struct {
	VendorDir string
}

// vendorPackageManifest is the subset of vendor/.../composer.json we read.
type vendorPackageManifest struct {
	License []string `json:"license,omitempty"`
}

// Resolve implements ComposerResolver.
func (r *VendorResolver) Resolve(name, _ string) (string, string) {
	if r.VendorDir == "" || name == "" {
		return "", ""
	}
	pkgDir := filepath.Join(r.VendorDir, name)
	pkgJSON := filepath.Join(pkgDir, manifestComposerJSON)

	if data, err := os.ReadFile(pkgJSON); err == nil {
		// composer.json `license` is a string-or-array union. Accept both.
		var single struct {
			License string `json:"license"`
		}
		if json.Unmarshal(data, &single) == nil && single.License != "" {
			return single.License, pkgJSON
		}
		var multi vendorPackageManifest
		if json.Unmarshal(data, &multi) == nil {
			if spdx := firstNonEmpty(multi.License); spdx != "" {
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
