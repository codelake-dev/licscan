package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

type stubCargoResolver struct {
	results map[string]struct{ spdx, source string }
}

func (s stubCargoResolver) Resolve(name, _ string) (string, string) {
	if r, ok := s.results[name]; ok {
		return r.spdx, r.source
	}
	return "", ""
}

// ── basic detection ────────────────────────────────────────────

func TestCargoName(t *testing.T) {
	require.Equal(t, "cargo", (&Cargo{}).Name())
}

func TestCargoReturnsNotFoundWhenNoCargoTOML(t *testing.T) {
	found, deps, err := (&Cargo{}).Detect(t.TempDir())
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, deps)
}

func TestCargoErrorsOnMalformedCargoTOML(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Cargo.toml": "this = is = not = valid = toml\n[[[",
	})
	found, _, err := (&Cargo{}).Detect(dir)
	require.Error(t, err)
	require.True(t, found)
}

// ── Cargo.lock — primary path ──────────────────────────────────

const sampleCargoTOML = `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }

[dev-dependencies]
mockall = "0.11"

[build-dependencies]
cc = "1.0"
`

const sampleCargoLock = `version = 3

[[package]]
name = "myapp"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "tokio"
version = "1.30.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "mockall"
version = "0.11.4"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "cc"
version = "1.0.83"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "transitive-only"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`

func TestCargoLockEmitsAllExternalPackages(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Cargo.toml": sampleCargoTOML,
		"Cargo.lock": sampleCargoLock,
	})

	det := &Cargo{Resolver: stubCargoResolver{}}
	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 5, "5 external deps (project itself excluded — no source field)")
}

func TestCargoLockSkipsProjectSelf(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Cargo.toml": sampleCargoTOML,
		"Cargo.lock": sampleCargoLock,
	})

	det := &Cargo{Resolver: stubCargoResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	for _, d := range deps {
		require.NotEqual(t, "myapp", d.Name,
			"the project itself (no source) must not appear in detected deps")
	}
}

func TestCargoLockMarksDirectVsTransitive(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Cargo.toml": sampleCargoTOML,
		"Cargo.lock": sampleCargoLock,
	})

	det := &Cargo{Resolver: stubCargoResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	direct := map[string]bool{}
	for _, d := range deps {
		direct[d.Name] = d.Direct
	}
	require.True(t, direct["serde"], "serde in [dependencies] → direct")
	require.True(t, direct["tokio"], "tokio in [dependencies] → direct")
	require.True(t, direct["mockall"], "mockall in [dev-dependencies] → direct")
	require.True(t, direct["cc"], "cc in [build-dependencies] → direct")
	require.False(t, direct["transitive-only"], "transitive-only not listed → transitive")
}

func TestCargoLockUsesResolverForLicenses(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Cargo.toml": sampleCargoTOML,
		"Cargo.lock": sampleCargoLock,
	})

	det := &Cargo{Resolver: stubCargoResolver{results: map[string]struct{ spdx, source string }{
		"serde":   {"MIT", "stub"},
		"tokio":   {"MIT", "stub"},
		"mockall": {"Apache-2.0", "stub"},
		"cc":      {"Apache-2.0", "stub"},
	}}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	bySource := map[string]scanner.Dependency{}
	for _, d := range deps {
		bySource[d.Name] = d
	}
	require.Equal(t, "MIT", bySource["serde"].PrimaryLicense())
	require.Equal(t, "Apache-2.0", bySource["cc"].PrimaryLicense())
	require.Equal(t, "Unknown", bySource["transitive-only"].PrimaryLicense(),
		"unresolved → Unknown with explanatory note")
}

// ── Cargo.toml without lockfile ────────────────────────────────

func TestCargoWithoutLockfileEmitsDirectOnly(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Cargo.toml": sampleCargoTOML,
	})

	det := &Cargo{Resolver: stubCargoResolver{results: map[string]struct{ spdx, source string }{
		"serde":   {"MIT", "stub"},
		"tokio":   {"MIT", "stub"},
		"mockall": {"Apache-2.0", "stub"},
		"cc":      {"Apache-2.0", "stub"},
	}}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.Len(t, deps, 4, "4 direct deps from Cargo.toml")

	for _, d := range deps {
		require.True(t, d.Direct)
		require.NotEmpty(t, d.Notes)
	}
}

// ── CargoCacheResolver ─────────────────────────────────────────

func TestCargoCacheResolverReadsLicenseFromCrateTOML(t *testing.T) {
	srcRoot := t.TempDir()
	indexDir := filepath.Join(srcRoot, "index.crates.io-abc123def456")
	crateDir := filepath.Join(indexDir, "serde-1.0.190")
	require.NoError(t, os.MkdirAll(crateDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(crateDir, "Cargo.toml"),
		[]byte(`[package]
name = "serde"
version = "1.0.190"
license = "MIT OR Apache-2.0"
`),
		0o644))

	r := &CargoCacheResolver{SrcRoot: srcRoot}
	spdx, source := r.Resolve("serde", "1.0.190")
	require.Equal(t, "MIT", spdx, "first identifier of SPDX expression wins")
	require.Contains(t, source, "Cargo.toml")
}

func TestCargoCacheResolverFallsBackToLicenseFile(t *testing.T) {
	srcRoot := t.TempDir()
	indexDir := filepath.Join(srcRoot, "index.crates.io-deadbeef")
	crateDir := filepath.Join(indexDir, "weird-1.0.0")
	require.NoError(t, os.MkdirAll(crateDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(crateDir, "Cargo.toml"),
		[]byte(`[package]
name = "weird"
version = "1.0.0"
license-file = "LICENSE-CUSTOM.txt"
`),
		0o644))
	require.NoError(t, os.WriteFile(
		filepath.Join(crateDir, "LICENSE"),
		[]byte("MIT License\nPermission is hereby granted, free of charge, to any person\nthe software is provided \"as is\""),
		0o644))

	r := &CargoCacheResolver{SrcRoot: srcRoot}
	spdx, source := r.Resolve("weird", "1.0.0")
	require.Equal(t, "MIT", spdx)
	require.Contains(t, source, "LICENSE")
}

func TestCargoCacheResolverHandlesMissingIndex(t *testing.T) {
	r := &CargoCacheResolver{SrcRoot: t.TempDir()}
	spdx, source := r.Resolve("any", "1.0")
	require.Equal(t, "", spdx)
	require.Equal(t, "", source)
}

func TestCargoCacheResolverHandlesEmptyInputs(t *testing.T) {
	r := &CargoCacheResolver{SrcRoot: ""}
	spdx, _ := r.Resolve("x", "1.0")
	require.Equal(t, "", spdx)

	r2 := &CargoCacheResolver{SrcRoot: t.TempDir()}
	spdx, _ = r2.Resolve("", "1.0")
	require.Equal(t, "", spdx)
	spdx, _ = r2.Resolve("x", "")
	require.Equal(t, "", spdx)
}

func TestDefaultCargoSrcRootHonoursCARGOHOME(t *testing.T) {
	t.Setenv("CARGO_HOME", filepath.Join(string(filepath.Separator), "custom", "cargo"))
	want := filepath.Join(string(filepath.Separator), "custom", "cargo", "registry", "src")
	require.Equal(t, want, defaultCargoSrcRoot())
}

func TestDefaultCargoSrcRootFallsBackToHome(t *testing.T) {
	t.Setenv("CARGO_HOME", "")
	root := defaultCargoSrcRoot()
	require.NotEmpty(t, root)
	// Use OS-native path separator so the assertion matches on Windows too.
	require.Contains(t, root, filepath.Join("registry", "src"))
}
