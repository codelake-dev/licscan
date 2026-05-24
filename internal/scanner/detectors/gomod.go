// Package detectors contains one scanner implementation per package manager.
package detectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/codelake-ai/licscan/internal/scanner"
)

// GoMod is the detector for Go modules (go.mod).
//
// It parses go.mod, extracts every required module (direct + indirect),
// and resolves each one's license via the injected LicenseResolver.
// The default resolver inspects $GOPATH/pkg/mod for the module's
// LICENSE / COPYING file and runs the SPDX text identifier.
type GoMod struct {
	Resolver LicenseResolver
}

// LicenseResolver looks up the license SPDX identifier for a Go module.
// Implementations may consult the local module cache, an SBOM file,
// or remote APIs — the detector doesn't care.
//
// Returns SPDX identifier, source label (where the license came from),
// or an empty SPDX if no confident match was found.
type LicenseResolver interface {
	Resolve(modulePath, version string) (spdx string, source string)
}

// Name implements scanner.Detector.
func (g *GoMod) Name() string {
	return "gomod"
}

// Detect implements scanner.Detector.
func (g *GoMod) Detect(rootPath string) (bool, []scanner.Dependency, error) {
	goModPath := filepath.Join(rootPath, "go.mod")

	raw, err := os.ReadFile(goModPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("read go.mod: %w", err)
	}

	mod, err := modfile.Parse(goModPath, raw, nil)
	if err != nil {
		return true, nil, fmt.Errorf("parse go.mod: %w", err)
	}

	resolver := g.Resolver
	if resolver == nil {
		resolver = NewLocalCacheResolver()
	}

	deps := make([]scanner.Dependency, 0, len(mod.Require))
	for _, req := range mod.Require {
		dep := scanner.Dependency{
			Name:      req.Mod.Path,
			Version:   req.Mod.Version,
			Ecosystem: "gomod",
			Manifest:  "go.mod",
			Direct:    !req.Indirect,
		}

		spdx, source := resolver.Resolve(req.Mod.Path, req.Mod.Version)
		if spdx == "" {
			dep.Licenses = []scanner.License{scanner.NewLicense("Unknown", "")}
			dep.Notes = append(dep.Notes,
				"license not found in local module cache — run `go mod download` first or use a remote resolver")
		} else {
			dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
		}
		deps = append(deps, dep)
	}

	return true, deps, nil
}

// LocalCacheResolver looks up license files inside the Go module cache,
// typically $GOPATH/pkg/mod (or $GOMODCACHE if set explicitly).
type LocalCacheResolver struct {
	CacheRoot string // overridable for tests
}

// NewLocalCacheResolver creates a resolver pointing at the local Go
// module cache. Falls back to $HOME/go/pkg/mod if neither GOMODCACHE
// nor GOPATH is set.
func NewLocalCacheResolver() *LocalCacheResolver {
	return &LocalCacheResolver{CacheRoot: defaultModCacheRoot()}
}

func defaultModCacheRoot() string {
	if c := os.Getenv("GOMODCACHE"); c != "" {
		return c
	}
	if g := os.Getenv("GOPATH"); g != "" {
		return filepath.Join(g, "pkg", "mod")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, "go", "pkg", "mod")
	}
	return ""
}

// LicenseFileNames is the prioritised list the resolver checks inside
// each module-cache directory. Exported so detectors / tests can re-use it.
var LicenseFileNames = []string{
	"LICENSE", "LICENSE.md", "LICENSE.txt",
	"LICENCE", "LICENCE.md", "LICENCE.txt",
	"COPYING", "COPYING.md",
	"License", "License.md",
}

// Resolve implements LicenseResolver against the local Go module cache.
func (r *LocalCacheResolver) Resolve(modulePath, version string) (string, string) {
	if r.CacheRoot == "" || modulePath == "" || version == "" {
		return "", ""
	}

	moduleDir := filepath.Join(r.CacheRoot, encodeModulePath(modulePath)+"@"+version)
	for _, name := range LicenseFileNames {
		path := filepath.Join(moduleDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		spdx := scanner.IdentifyLicense(string(data))
		if spdx == "" {
			// File exists but we can't classify it — return Unknown with
			// the path so the user knows where to inspect manually.
			return "", path
		}
		return spdx, path
	}
	return "", ""
}

// encodeModulePath replicates Go module-cache path escaping: capital
// letters become '!' + lowercase (e.g. github.com/Foo/Bar → github.com/!foo/!bar).
// This matches the on-disk layout that `go mod download` creates.
func encodeModulePath(p string) string {
	var b strings.Builder
	b.Grow(len(p))
	for _, r := range p {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
