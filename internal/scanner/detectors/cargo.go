package detectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// Cargo is the detector for Rust projects (Cargo.toml + Cargo.lock).
//
// Cargo.lock pins every dep (direct + transitive) but does NOT carry
// license info — Rust developers traditionally look it up via crates.io.
// We resolve from the local cargo cache at $CARGO_HOME/registry/src/...
// where downloaded crate sources include their Cargo.toml.
type Cargo struct {
	Resolver CargoResolver
}

// CargoResolver looks up a license for a crate by name+version.
type CargoResolver interface {
	Resolve(name, version string) (spdx string, source string)
}

// Name implements scanner.Detector.
func (c *Cargo) Name() string {
	return "cargo"
}

// Detect implements scanner.Detector.
func (c *Cargo) Detect(rootPath string) (bool, []scanner.Dependency, error) {
	cargoTOMLPath := filepath.Join(rootPath, "Cargo.toml")
	rawTOML, err := os.ReadFile(cargoTOMLPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("read Cargo.toml: %w", err)
	}

	var manifest cargoManifest
	if err := toml.Unmarshal(rawTOML, &manifest); err != nil {
		return true, nil, fmt.Errorf("parse Cargo.toml: %w", err)
	}

	resolver := c.Resolver
	if resolver == nil {
		resolver = NewCargoCacheResolver()
	}

	directNames := manifest.directDependencyNames()

	// Prefer Cargo.lock for full transitive coverage.
	lockPath := filepath.Join(rootPath, "Cargo.lock")
	if rawLock, lockErr := os.ReadFile(lockPath); lockErr == nil {
		var lock cargoLock
		if err := toml.Unmarshal(rawLock, &lock); err != nil {
			return true, nil, fmt.Errorf("parse Cargo.lock: %w", err)
		}
		return true, cargoDepsFromLock(lock, directNames, resolver), nil
	}

	// No lockfile — direct deps only.
	deps := make([]scanner.Dependency, 0, len(manifest.Dependencies)+len(manifest.DevDependencies))
	for name := range manifest.allDirectDependencies() {
		dep := newCargoDependency(name, "", true, resolver)
		dep.Notes = append(dep.Notes,
			"Cargo.lock missing — transitive dependencies were not analysed; run `cargo generate-lockfile`")
		deps = append(deps, dep)
	}
	return true, deps, nil
}

// ── Cargo.toml types ───────────────────────────────────────────

type cargoManifest struct {
	Dependencies    map[string]toml.Primitive `toml:"dependencies"`
	DevDependencies map[string]toml.Primitive `toml:"dev-dependencies"`
	BuildDeps       map[string]toml.Primitive `toml:"build-dependencies"`
}

func (m cargoManifest) directDependencyNames() map[string]bool {
	out := make(map[string]bool)
	for name := range m.Dependencies {
		out[name] = true
	}
	for name := range m.DevDependencies {
		out[name] = true
	}
	for name := range m.BuildDeps {
		out[name] = true
	}
	return out
}

func (m cargoManifest) allDirectDependencies() map[string]bool {
	return m.directDependencyNames()
}

// ── Cargo.lock types ───────────────────────────────────────────

type cargoLock struct {
	Packages []cargoLockPackage `toml:"package"`
}

type cargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Source  string `toml:"source"`
}

func cargoDepsFromLock(lock cargoLock, directNames map[string]bool, resolver CargoResolver) []scanner.Dependency {
	deps := make([]scanner.Dependency, 0, len(lock.Packages))
	for _, pkg := range lock.Packages {
		// Cargo.lock includes the project itself as a package entry with
		// no `source`. Skip it — it's not a third-party dep.
		if pkg.Source == "" {
			continue
		}

		dep := scanner.Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "cargo",
			Manifest:  "Cargo.lock",
			Direct:    directNames[pkg.Name],
		}

		spdx := ""
		source := ""
		if resolver != nil {
			spdx, source = resolver.Resolve(pkg.Name, pkg.Version)
		}

		if spdx == "" {
			dep.Licenses = []scanner.License{scanner.NewLicense("Unknown", "")}
			dep.Notes = append(dep.Notes,
				"license not found in local cargo cache — run `cargo fetch` first")
		} else {
			dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
		}
		deps = append(deps, dep)
	}
	return deps
}

// ── Dependency construction ────────────────────────────────────

func newCargoDependency(name, version string, direct bool, resolver CargoResolver) scanner.Dependency {
	dep := scanner.Dependency{
		Name:      name,
		Version:   version,
		Ecosystem: "cargo",
		Manifest:  "Cargo.toml",
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
			"license could not be resolved — run `cargo fetch` to populate the local cache")
	} else {
		dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
	}
	return dep
}

// ── CargoCacheResolver ─────────────────────────────────────────

// CargoCacheResolver inspects $CARGO_HOME/registry/src/index.crates.io-XXX/
// <name>-<version>/Cargo.toml for the [package].license field.
type CargoCacheResolver struct {
	SrcRoot string // typically $CARGO_HOME/registry/src
}

// NewCargoCacheResolver builds a resolver pointing at the local cargo
// source cache.
func NewCargoCacheResolver() *CargoCacheResolver {
	return &CargoCacheResolver{SrcRoot: defaultCargoSrcRoot()}
}

func defaultCargoSrcRoot() string {
	if c := os.Getenv("CARGO_HOME"); c != "" {
		return filepath.Join(c, "registry", "src")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".cargo", "registry", "src")
	}
	return ""
}

// cratePackageTable is the subset of a crate's Cargo.toml we read.
type cratePackageTable struct {
	Package struct {
		License     string `toml:"license"`
		LicenseFile string `toml:"license-file"`
	} `toml:"package"`
}

// Resolve implements CargoResolver.
func (r *CargoCacheResolver) Resolve(name, version string) (string, string) {
	if r.SrcRoot == "" || name == "" || version == "" {
		return "", ""
	}

	indexDir := r.findIndexDir()
	if indexDir == "" {
		return "", ""
	}

	crateDir := filepath.Join(indexDir, name+"-"+version)
	cratePath := filepath.Join(crateDir, "Cargo.toml")

	if data, err := os.ReadFile(cratePath); err == nil {
		var ct cratePackageTable
		if toml.Unmarshal(data, &ct) == nil && ct.Package.License != "" {
			return cleanLicenseString(ct.Package.License), cratePath
		}
	}

	// Fall back to LICENSE-file text scan in the crate dir.
	for _, fname := range LicenseFileNames {
		path := filepath.Join(crateDir, fname)
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

// findIndexDir locates the index.crates.io-<hash> subdirectory inside
// SrcRoot. The hash suffix varies between cargo versions; we just match
// the prefix.
func (r *CargoCacheResolver) findIndexDir() string {
	entries, err := os.ReadDir(r.SrcRoot)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "index.crates.io-") {
			return filepath.Join(r.SrcRoot, e.Name())
		}
	}
	return ""
}
