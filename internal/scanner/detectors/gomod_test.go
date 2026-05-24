package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-ai/licscan/internal/scanner"
)

// stubResolver is a fake LicenseResolver used to drive the detector's
// branches without touching the real module cache.
type stubResolver struct {
	results map[string]struct {
		spdx, source string
	}
}

func (s stubResolver) Resolve(module, _ string) (string, string) {
	if r, ok := s.results[module]; ok {
		return r.spdx, r.source
	}
	return "", ""
}

const sampleGoMod = `module github.com/example/app

go 1.22

require (
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.2 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)
`

func writeTempGoMod(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644))
	return dir
}

func TestGoModName(t *testing.T) {
	require.Equal(t, "gomod", (&GoMod{}).Name())
}

func TestGoModDetectsAllDependencies(t *testing.T) {
	root := writeTempGoMod(t, sampleGoMod)
	det := &GoMod{Resolver: stubResolver{results: map[string]struct{ spdx, source string }{
		"github.com/spf13/cobra":        {"Apache-2.0", "stub"},
		"github.com/stretchr/testify":   {"MIT", "stub"},
		"github.com/davecgh/go-spew":    {"ISC", "stub"},
		"github.com/spf13/pflag":        {"BSD-3-Clause", "stub"},
	}}}

	found, deps, err := det.Detect(root)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 4)

	names := make([]string, len(deps))
	for i, d := range deps {
		names[i] = d.Name
	}
	require.Contains(t, names, "github.com/spf13/cobra")
	require.Contains(t, names, "github.com/spf13/pflag")
}

func TestGoModDistinguishesDirectFromIndirect(t *testing.T) {
	root := writeTempGoMod(t, sampleGoMod)
	det := &GoMod{Resolver: stubResolver{}}

	_, deps, err := det.Detect(root)
	require.NoError(t, err)

	direct := map[string]bool{}
	for _, d := range deps {
		direct[d.Name] = d.Direct
	}
	require.True(t, direct["github.com/spf13/cobra"], "cobra is a direct dep")
	require.False(t, direct["github.com/spf13/pflag"], "pflag is // indirect")
	require.False(t, direct["github.com/davecgh/go-spew"], "go-spew is // indirect")
}

func TestGoModAssignsRiskFromResolvedLicense(t *testing.T) {
	root := writeTempGoMod(t, sampleGoMod)
	det := &GoMod{Resolver: stubResolver{results: map[string]struct{ spdx, source string }{
		"github.com/spf13/cobra": {"Apache-2.0", "/cache/cobra/LICENSE"},
	}}}

	_, deps, err := det.Detect(root)
	require.NoError(t, err)

	for _, d := range deps {
		if d.Name == "github.com/spf13/cobra" {
			require.Equal(t, "Apache-2.0", d.PrimaryLicense())
			require.Equal(t, scanner.RiskPermissive, d.PrimaryRisk())
			require.Equal(t, "/cache/cobra/LICENSE", d.Licenses[0].Source)
		}
	}
}

func TestGoModMarksUnresolvedAsUnknownWithNote(t *testing.T) {
	root := writeTempGoMod(t, sampleGoMod)
	det := &GoMod{Resolver: stubResolver{}} // resolves nothing

	_, deps, err := det.Detect(root)
	require.NoError(t, err)

	for _, d := range deps {
		require.Equal(t, "Unknown", d.PrimaryLicense(),
			"unresolved dep %s must be marked Unknown", d.Name)
		require.NotEmpty(t, d.Notes, "unresolved dep must carry an explanatory note")
	}
}

func TestGoModReturnsNotFoundWhenNoGoMod(t *testing.T) {
	det := &GoMod{Resolver: stubResolver{}}
	emptyDir := t.TempDir()

	found, deps, err := det.Detect(emptyDir)
	require.NoError(t, err, "missing go.mod is not an error")
	require.False(t, found)
	require.Nil(t, deps)
}

func TestGoModErrorsOnMalformedManifest(t *testing.T) {
	root := writeTempGoMod(t, "this is not a valid go.mod\n@@@\n")
	det := &GoMod{Resolver: stubResolver{}}

	found, _, err := det.Detect(root)
	require.Error(t, err, "malformed go.mod must surface as detector error")
	require.True(t, found, "manifest was found, even if unparseable")
}

func TestEncodeModulePathLowercasesCapitals(t *testing.T) {
	require.Equal(t, "github.com/foo/bar", encodeModulePath("github.com/foo/bar"))
	require.Equal(t, "github.com/!foo/!bar", encodeModulePath("github.com/Foo/Bar"))
	require.Equal(t, "github.com/!a!w!s/!s!d!k", encodeModulePath("github.com/AWS/SDK"))
}

func TestLocalCacheResolverFindsLicenseFile(t *testing.T) {
	cache := t.TempDir()
	moduleDir := filepath.Join(cache, "example.com", "lib@v1.0.0")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(moduleDir, "LICENSE"),
		[]byte("MIT License\n\nPermission is hereby granted, free of charge, to any person\nthe software is provided \"as is\""),
		0o644))

	r := &LocalCacheResolver{CacheRoot: cache}
	spdx, source := r.Resolve("example.com/lib", "v1.0.0")

	require.Equal(t, "MIT", spdx)
	require.Contains(t, source, "LICENSE")
}

func TestLocalCacheResolverHandlesMissingModule(t *testing.T) {
	r := &LocalCacheResolver{CacheRoot: t.TempDir()}
	spdx, source := r.Resolve("nonexistent/module", "v1.0.0")
	require.Equal(t, "", spdx)
	require.Equal(t, "", source)
}

func TestLocalCacheResolverHandlesEmptyInputs(t *testing.T) {
	r := &LocalCacheResolver{CacheRoot: ""}
	spdx, _ := r.Resolve("any", "v1.0.0")
	require.Equal(t, "", spdx)

	r2 := &LocalCacheResolver{CacheRoot: t.TempDir()}
	spdx, _ = r2.Resolve("", "v1.0.0")
	require.Equal(t, "", spdx)
	spdx, _ = r2.Resolve("x", "")
	require.Equal(t, "", spdx)
}

func TestLocalCacheResolverReturnsPathWhenLicenseUnidentified(t *testing.T) {
	cache := t.TempDir()
	moduleDir := filepath.Join(cache, "example.com", "lib@v1.0.0")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(moduleDir, "LICENSE"),
		[]byte("Some Custom Corporate License\nAll rights reserved.\n"),
		0o644))

	r := &LocalCacheResolver{CacheRoot: cache}
	spdx, source := r.Resolve("example.com/lib", "v1.0.0")

	require.Equal(t, "", spdx, "unidentified license stays empty")
	require.Contains(t, source, "LICENSE", "but the source path is surfaced for human inspection")
}

func TestLocalCacheResolverTriesAlternativeLicenseFilenames(t *testing.T) {
	cache := t.TempDir()
	moduleDir := filepath.Join(cache, "example.com", "old@v0.1.0")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(moduleDir, "COPYING"),
		[]byte("MIT License\nPermission is hereby granted, free of charge, to any person\nthe software is provided \"as is\""),
		0o644))

	r := &LocalCacheResolver{CacheRoot: cache}
	spdx, _ := r.Resolve("example.com/old", "v0.1.0")
	require.Equal(t, "MIT", spdx)
}

func TestLocalCacheResolverEscapesCapitalLetters(t *testing.T) {
	cache := t.TempDir()
	moduleDir := filepath.Join(cache, "github.com", "!a!w!s", "!s!d!k@v2.0.0")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(moduleDir, "LICENSE"),
		[]byte("Apache License\nVersion 2.0"),
		0o644))

	r := &LocalCacheResolver{CacheRoot: cache}
	spdx, _ := r.Resolve("github.com/AWS/SDK", "v2.0.0")
	require.Equal(t, "Apache-2.0", spdx)
}

func TestDefaultModCacheRootFallsBackToHome(t *testing.T) {
	t.Setenv("GOMODCACHE", "")
	t.Setenv("GOPATH", "")
	root := defaultModCacheRoot()
	require.NotEmpty(t, root, "must produce some path (HOME fallback)")
}

func TestDefaultModCacheRootHonoursGOMODCACHE(t *testing.T) {
	t.Setenv("GOMODCACHE", "/custom/mod/cache")
	require.Equal(t, "/custom/mod/cache", defaultModCacheRoot())
}

func TestDefaultModCacheRootFallsBackToGOPATH(t *testing.T) {
	t.Setenv("GOMODCACHE", "")
	t.Setenv("GOPATH", "/my/gopath")
	require.Equal(t, "/my/gopath/pkg/mod", defaultModCacheRoot())
}
