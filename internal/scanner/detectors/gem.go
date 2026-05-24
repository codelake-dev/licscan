package detectors

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// Gem is the detector for Ruby projects (Gemfile + Gemfile.lock).
//
// Gemfile.lock has its own line-based format (not YAML / JSON / TOML).
// We parse the GEM specs: section for pinned versions and the
// DEPENDENCIES section for the direct-deps list.
//
// License resolution: tries vendor/bundle/ruby/<X.Y.Z>/gems/<name>-<ver>/
// first (the conventional bundler install path), then $GEM_HOME. Gemspecs
// are Ruby source — we regex-extract the `s.license = "..."` line rather
// than executing Ruby.
type Gem struct {
	Resolver GemResolver
}

// GemResolver looks up a license for a Ruby gem by name+version.
type GemResolver interface {
	Resolve(name, version string) (spdx string, source string)
}

// Name implements scanner.Detector.
func (g *Gem) Name() string {
	return ecosystemGem
}

// Detect implements scanner.Detector.
func (g *Gem) Detect(rootPath string) (bool, []scanner.Dependency, error) {
	lockPath := filepath.Join(rootPath, manifestGemfileLock)
	rawLock, err := os.ReadFile(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("read Gemfile.lock: %w", err)
	}

	specs, directs, err := parseGemfileLock(rawLock)
	if err != nil {
		return true, nil, fmt.Errorf("parse Gemfile.lock: %w", err)
	}

	resolver := g.Resolver
	if resolver == nil {
		resolver = NewBundlerOrGemHomeResolver(rootPath)
	}

	directSet := make(map[string]bool, len(directs))
	for _, d := range directs {
		directSet[d] = true
	}

	deps := make([]scanner.Dependency, 0, len(specs))
	for _, spec := range specs {
		dep := scanner.Dependency{
			Name:      spec.Name,
			Version:   spec.Version,
			Ecosystem: ecosystemGem,
			Manifest:  manifestGemfileLock,
			Direct:    directSet[spec.Name],
		}

		spdx, source := resolver.Resolve(spec.Name, spec.Version)
		if spdx == "" {
			dep.Licenses = []scanner.License{scanner.NewLicense("Unknown", "")}
			dep.Notes = append(dep.Notes,
				"license not found in vendor/bundle or \\$GEM_HOME — run `bundle install` first")
		} else {
			dep.Licenses = []scanner.License{scanner.NewLicense(spdx, source)}
		}
		deps = append(deps, dep)
	}
	return true, deps, nil
}

// ── Gemfile.lock parser ────────────────────────────────────────

// GemSpec is one pinned (name, version) entry from the GEM specs section.
type GemSpec struct {
	Name    string
	Version string
}

var (
	specEntryRegex       = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([^)]+)\)$`)
	dependencyEntryRegex = regexp.MustCompile(`^  ([A-Za-z0-9._-]+)`)
)

// parseGemfileLock walks the lockfile in a tiny state-machine, returning
// the pinned specs and the direct-deps name list. Sections we don't care
// about (PLATFORMS, BUNDLED WITH, RUBY VERSION) are ignored.
func parseGemfileLock(raw []byte) (specs []GemSpec, directs []string, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	type state int
	const (
		outside state = iota
		inSpecs
		inDependencies
	)

	current := outside
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Section transitions
		switch trimmed {
		case "GEM":
			current = outside
			continue
		case "specs:":
			if current == outside {
				current = inSpecs
			}
			continue
		case "DEPENDENCIES":
			current = inDependencies
			continue
		case "PLATFORMS", "BUNDLED WITH", "RUBY VERSION":
			current = outside
			continue
		}
		if trimmed == "" {
			current = outside
			continue
		}

		switch current {
		case inSpecs:
			if m := specEntryRegex.FindStringSubmatch(line); m != nil {
				specs = append(specs, GemSpec{Name: m[1], Version: m[2]})
			}
			// 6-space-indented lines are nested requirements — skip.
		case inDependencies:
			if m := dependencyEntryRegex.FindStringSubmatch(line); m != nil {
				directs = append(directs, m[1])
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return specs, directs, nil
}

// ── BundlerOrGemHomeResolver ───────────────────────────────────

// BundlerOrGemHomeResolver tries vendor/bundle (most common in CI /
// containerised setups) first, then $GEM_HOME. Reads .gemspec files via
// regex extraction (gemspecs are Ruby source).
type BundlerOrGemHomeResolver struct {
	ProjectRoot string
	GemHome     string // override for tests
}

// NewBundlerOrGemHomeResolver returns a resolver wired to the given
// project root + the system $GEM_HOME.
func NewBundlerOrGemHomeResolver(projectRoot string) *BundlerOrGemHomeResolver {
	return &BundlerOrGemHomeResolver{
		ProjectRoot: projectRoot,
		GemHome:     os.Getenv("GEM_HOME"),
	}
}

// Resolve implements GemResolver.
func (r *BundlerOrGemHomeResolver) Resolve(name, version string) (string, string) {
	if name == "" || version == "" {
		return "", ""
	}

	// Try every candidate gems directory.
	for _, candidate := range r.candidateGemDirs() {
		gemDir := filepath.Join(candidate, name+"-"+version)
		if spdx, source := r.inspectGemDir(gemDir, name); spdx != "" || source != "" {
			return spdx, source
		}
	}
	return "", ""
}

func (r *BundlerOrGemHomeResolver) candidateGemDirs() []string {
	var dirs []string

	// vendor/bundle/ruby/<X.Y.Z>/gems/ — bundler's local-install layout
	if r.ProjectRoot != "" {
		vendorRubyRoot := filepath.Join(r.ProjectRoot, "vendor", "bundle", "ruby")
		if entries, err := os.ReadDir(vendorRubyRoot); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					dirs = append(dirs, filepath.Join(vendorRubyRoot, e.Name(), "gems"))
				}
			}
		}
	}

	// $GEM_HOME/gems
	if r.GemHome != "" {
		dirs = append(dirs, filepath.Join(r.GemHome, "gems"))
	}

	return dirs
}

var gemspecLicenseRegex = regexp.MustCompile(`(?m)^\s*(?:s|spec)\.licenses?\s*=\s*(.+?)$`)

// inspectGemDir reads <gemDir>/<name>.gemspec (regex-extracted), then
// falls back to LICENSE-file scan in the gem directory.
func (r *BundlerOrGemHomeResolver) inspectGemDir(gemDir, name string) (string, string) {
	gemspecPath := filepath.Join(gemDir, name+".gemspec")
	if data, err := os.ReadFile(gemspecPath); err == nil {
		if spdx := extractLicenseFromGemspec(data); spdx != "" {
			return spdx, gemspecPath
		}
	}

	for _, fname := range LicenseFileNames {
		path := filepath.Join(gemDir, fname)
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

// extractLicenseFromGemspec pulls the SPDX ID out of a Ruby gemspec
// without executing Ruby. Handles both common forms:
//
//	s.license = "MIT"
//	s.licenses = ["MIT", "Apache-2.0"]
func extractLicenseFromGemspec(data []byte) string {
	m := gemspecLicenseRegex.FindStringSubmatch(string(data))
	if m == nil {
		return ""
	}
	raw := strings.TrimSpace(m[1])

	// Strip array brackets if present.
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")

	// Take first quoted string.
	first := firstQuotedSubstring(raw)
	return first
}

// firstQuotedSubstring returns the contents of the first "..." or '...'
// literal in the string. Returns "" if none found.
func firstQuotedSubstring(s string) string {
	for _, quote := range []byte{'"', '\''} {
		start := strings.IndexByte(s, quote)
		if start < 0 {
			continue
		}
		end := strings.IndexByte(s[start+1:], quote)
		if end < 0 {
			continue
		}
		return s[start+1 : start+1+end]
	}
	return ""
}
