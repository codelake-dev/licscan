package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// stubNpmResolver returns canned licenses keyed by package name.
type stubNpmResolver struct {
	results map[string]struct{ spdx, source string }
}

func (s stubNpmResolver) Resolve(name, _ string) (string, string) {
	if r, ok := s.results[name]; ok {
		return r.spdx, r.source
	}
	return "", ""
}

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	return dir
}

// ── basic detection ────────────────────────────────────────────

func TestNpmName(t *testing.T) {
	require.Equal(t, "npm", (&Npm{}).Name())
}

func TestNpmReturnsNotFoundWhenNoPackageJSON(t *testing.T) {
	found, deps, err := (&Npm{}).Detect(t.TempDir())
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, deps)
}

func TestNpmErrorsOnMalformedPackageJSON(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": "this is not valid json {{{",
	})
	found, _, err := (&Npm{}).Detect(dir)
	require.Error(t, err)
	require.True(t, found, "manifest was found, even if unparseable")
}

// ── package.json without lockfile (direct deps only) ───────────

func TestNpmWithoutLockfileEmitsOnlyDirectDeps(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{
			"name": "app", "version": "1.0.0",
			"dependencies": {"lodash": "^4.17.21", "axios": "^1.0.0"},
			"devDependencies": {"jest": "^29.0.0"}
		}`,
	})

	det := &Npm{Resolver: stubNpmResolver{results: map[string]struct{ spdx, source string }{
		"lodash": {"MIT", "stub"},
		"axios":  {"MIT", "stub"},
		"jest":   {"MIT", "stub"},
	}}}

	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 3)

	for _, d := range deps {
		require.True(t, d.Direct, "all deps from package.json must be marked direct: %s", d.Name)
		require.NotEmpty(t, d.Notes, "missing-lockfile must surface a warning Note")
	}
}

// ── package-lock.json v2/v3 (inline license) ───────────────────

const lockfileV3 = `{
	"name": "app", "version": "1.0.0", "lockfileVersion": 3,
	"requires": true,
	"packages": {
		"": {"name": "app", "version": "1.0.0", "dependencies": {"lodash": "^4.17.21"}},
		"node_modules/lodash": {"version": "4.17.21", "license": "MIT"},
		"node_modules/axios": {"version": "1.6.0", "license": "MIT"},
		"node_modules/@babel/core": {"version": "7.23.0", "license": "MIT"},
		"node_modules/some-gpl-lib": {"version": "2.0.0", "license": "GPL-3.0"}
	}
}`

func TestNpmV3LockfileUsesInlineLicense(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}`,
		"package-lock.json": lockfileV3,
	})

	det := &Npm{Resolver: stubNpmResolver{}}
	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 4)

	bySource := map[string]scanner.Dependency{}
	for _, d := range deps {
		bySource[d.Name] = d
	}
	require.Equal(t, "MIT", bySource["lodash"].PrimaryLicense())
	require.Equal(t, "GPL-3.0", bySource["some-gpl-lib"].PrimaryLicense())
	require.Equal(t, scanner.RiskStrongCopyleft, bySource["some-gpl-lib"].PrimaryRisk())
	require.Equal(t, "@babel/core", bySource["@babel/core"].Name, "scoped packages handled correctly")
}

func TestNpmV3LockfileMarksDirectDeps(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}`,
		"package-lock.json": lockfileV3,
	})

	det := &Npm{Resolver: stubNpmResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	direct := map[string]bool{}
	for _, d := range deps {
		direct[d.Name] = d.Direct
	}
	require.True(t, direct["lodash"], "lodash is listed in package.json dependencies → direct")
	require.False(t, direct["axios"], "axios is transitive → not direct")
	require.False(t, direct["some-gpl-lib"], "some-gpl-lib is transitive → not direct")
}

// ── package-lock.json v1 (nested tree, resolver-based licenses) ─

const lockfileV1 = `{
	"name": "app", "version": "1.0.0", "lockfileVersion": 1,
	"dependencies": {
		"lodash": {"version": "4.17.21"},
		"axios": {
			"version": "1.6.0",
			"dependencies": {
				"follow-redirects": {"version": "1.15.0"}
			}
		}
	}
}`

func TestNpmV1LockfileWalksNestedTree(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.21","axios":"^1.0.0"}}`,
		"package-lock.json": lockfileV1,
	})

	det := &Npm{Resolver: stubNpmResolver{results: map[string]struct{ spdx, source string }{
		"lodash":           {"MIT", "stub"},
		"axios":            {"MIT", "stub"},
		"follow-redirects": {"MIT", "stub"},
	}}}

	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 3, "v1 must walk nested deps (axios → follow-redirects)")
}

// ── license-field shape variations ─────────────────────────────

func TestExtractLicenseFromString(t *testing.T) {
	require.Equal(t, "MIT", extractLicenseFromRawMessage([]byte(`"MIT"`)))
}

func TestExtractLicenseFromObject(t *testing.T) {
	require.Equal(t, "Apache-2.0",
		extractLicenseFromRawMessage([]byte(`{"type":"Apache-2.0","url":"http://..."}`)))
}

func TestExtractLicenseFromArray(t *testing.T) {
	require.Equal(t, "MIT",
		extractLicenseFromRawMessage([]byte(`[{"type":"MIT"},{"type":"Apache-2.0"}]`)))
}

func TestExtractLicenseFromSPDXExpression(t *testing.T) {
	require.Equal(t, "MIT", extractLicenseFromRawMessage([]byte(`"(MIT OR Apache-2.0)"`)))
}

func TestExtractLicenseHandlesSEELICENSEIndirection(t *testing.T) {
	require.Equal(t, "", extractLicenseFromRawMessage([]byte(`"SEE LICENSE IN LICENSE.md"`)),
		"SEE LICENSE indirection must return empty so resolver falls back to file scan")
}

func TestExtractLicenseFromEmpty(t *testing.T) {
	require.Equal(t, "", extractLicenseFromRawMessage(nil))
	require.Equal(t, "", extractLicenseFromRawMessage([]byte(``)))
}

func TestExtractLicenseFromUnlicensed(t *testing.T) {
	// UNLICENSED passes through — not Unknown, but explicitly marked.
	require.Equal(t, "UNLICENSED", extractLicenseFromRawMessage([]byte(`"UNLICENSED"`)))
}

// ── nameFromLockfileKey ────────────────────────────────────────

func TestNameFromLockfileKeySimple(t *testing.T) {
	require.Equal(t, "lodash", nameFromLockfileKey("node_modules/lodash"))
}

func TestNameFromLockfileKeyScoped(t *testing.T) {
	require.Equal(t, "@babel/core", nameFromLockfileKey("node_modules/@babel/core"))
}

func TestNameFromLockfileKeyNested(t *testing.T) {
	// Nested node_modules → take the leaf package.
	require.Equal(t, "leaf",
		nameFromLockfileKey("node_modules/parent/node_modules/leaf"))
}

func TestNameFromLockfileKeyEmpty(t *testing.T) {
	require.Equal(t, "", nameFromLockfileKey(""))
	require.Equal(t, "", nameFromLockfileKey("just/a/path"))
}

// ── NodeModulesResolver ────────────────────────────────────────

func TestNodeModulesResolverReadsLicenseFromPackageJSON(t *testing.T) {
	nm := t.TempDir()
	pkgDir := filepath.Join(nm, "lodash")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(pkgDir, "package.json"),
		[]byte(`{"name":"lodash","version":"4.17.21","license":"MIT"}`),
		0o644))

	r := &NodeModulesResolver{NodeModulesDir: nm}
	spdx, source := r.Resolve("lodash", "4.17.21")
	require.Equal(t, "MIT", spdx)
	require.Contains(t, source, "package.json")
}

func TestNodeModulesResolverFallsBackToLicenseFile(t *testing.T) {
	nm := t.TempDir()
	pkgDir := filepath.Join(nm, "weird-pkg")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(pkgDir, "package.json"),
		[]byte(`{"name":"weird-pkg","version":"1.0.0"}`),
		0o644))
	require.NoError(t, os.WriteFile(
		filepath.Join(pkgDir, "LICENSE"),
		[]byte("Apache License\nVersion 2.0"),
		0o644))

	r := &NodeModulesResolver{NodeModulesDir: nm}
	spdx, source := r.Resolve("weird-pkg", "1.0.0")
	require.Equal(t, "Apache-2.0", spdx)
	require.Contains(t, source, "LICENSE")
}

func TestNodeModulesResolverHandlesMissingPackage(t *testing.T) {
	r := &NodeModulesResolver{NodeModulesDir: t.TempDir()}
	spdx, source := r.Resolve("nope", "1.0.0")
	require.Equal(t, "", spdx)
	require.Equal(t, "", source)
}

func TestNodeModulesResolverHandlesEmptyInputs(t *testing.T) {
	r := &NodeModulesResolver{}
	spdx, _ := r.Resolve("anything", "1.0.0")
	require.Equal(t, "", spdx)

	r2 := &NodeModulesResolver{NodeModulesDir: t.TempDir()}
	spdx, _ = r2.Resolve("", "1.0.0")
	require.Equal(t, "", spdx)
}

// ── direct-dep tracking across all four buckets ────────────────

func TestPackageJSONDirectDependencyNamesIncludesAllBuckets(t *testing.T) {
	pkg := packageJSON{
		Dependencies:         map[string]string{"a": ""},
		DevDependencies:      map[string]string{"b": ""},
		PeerDependencies:     map[string]string{"c": ""},
		OptionalDependencies: map[string]string{"d": ""},
	}
	names := pkg.directDependencyNames()
	require.True(t, names["a"])
	require.True(t, names["b"])
	require.True(t, names["c"])
	require.True(t, names["d"])
	require.False(t, names["e"])
}
