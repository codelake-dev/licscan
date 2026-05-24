package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubPipResolver struct {
	results map[string]struct{ spdx, source string }
}

func (s stubPipResolver) Resolve(name, _ string) (string, string) {
	if r, ok := s.results[name]; ok {
		return r.spdx, r.source
	}
	return "", ""
}

// ── basic detection ────────────────────────────────────────────

func TestPipName(t *testing.T) {
	require.Equal(t, "pip", (&Pip{}).Name())
}

func TestPipReturnsNotFoundWhenNoManifests(t *testing.T) {
	found, deps, err := (&Pip{}).Detect(t.TempDir())
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, deps)
}

// ── poetry.lock ────────────────────────────────────────────────

const samplePoetryLock = `[[package]]
name = "django"
version = "4.2.7"
description = "A high-level Python Web framework"
optional = false
python-versions = ">=3.8"

[[package]]
name = "psycopg2-binary"
version = "2.9.9"
description = "psycopg2 - Python-PostgreSQL Database Adapter"
optional = false
python-versions = "*"

[[package]]
name = "asgiref"
version = "3.7.2"
description = "ASGI specs, helper code, and adapters"
optional = false
python-versions = ">=3.7"
`

const samplePyprojectPoetry = `[tool.poetry]
name = "myapp"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.10"
django = "^4.2"
psycopg2-binary = "^2.9"
`

func TestPoetryLockParsesAllPackages(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"poetry.lock":     samplePoetryLock,
		"pyproject.toml":  samplePyprojectPoetry,
	})
	det := &Pip{Resolver: stubPipResolver{}}
	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 3)
}

func TestPoetryLockMarksDirectVsTransitive(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"poetry.lock":    samplePoetryLock,
		"pyproject.toml": samplePyprojectPoetry,
	})
	det := &Pip{Resolver: stubPipResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	direct := map[string]bool{}
	for _, d := range deps {
		direct[d.Name] = d.Direct
	}
	require.True(t, direct["django"])
	require.True(t, direct["psycopg2-binary"])
	require.False(t, direct["asgiref"], "asgiref only in poetry.lock, not pyproject.toml")
}

func TestPoetryLockErrorsOnMalformedTOML(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"poetry.lock": "this is not [[ valid toml",
	})
	_, _, err := (&Pip{}).Detect(dir)
	require.Error(t, err)
}

// ── Pipfile.lock ───────────────────────────────────────────────

const samplePipfileLock = `{
	"_meta": {"hash": {"sha256": "abc"}},
	"default": {
		"django": {"version": "==4.2.7", "hashes": []},
		"requests": {"version": "==2.31.0", "hashes": []}
	},
	"develop": {
		"pytest": {"version": "==7.4.3", "hashes": []}
	}
}`

func TestPipfileLockParsesDefaultAndDevelop(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Pipfile.lock": samplePipfileLock,
	})
	det := &Pip{Resolver: stubPipResolver{}}
	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 3)

	versions := map[string]string{}
	for _, d := range deps {
		versions[d.Name] = d.Version
	}
	require.Equal(t, "4.2.7", versions["django"], "version stripped of == prefix")
	require.Equal(t, "7.4.3", versions["pytest"])
}

func TestPipfileLockErrorsOnMalformedJSON(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"Pipfile.lock": "{{{ not json",
	})
	_, _, err := (&Pip{}).Detect(dir)
	require.Error(t, err)
}

// ── requirements.txt ───────────────────────────────────────────

func TestRequirementsTxtParsesPinnedVersions(t *testing.T) {
	got := parseRequirementsTxt([]byte(`# this is a comment
django==4.2.7
psycopg2-binary>=2.9.0
flask  # trailing comment

requests
-r requirements-dev.txt
https://example.com/some-package.tar.gz
`))
	require.Equal(t, "4.2.7", got["django"], "exact pin captured")
	require.Equal(t, "", got["psycopg2-binary"], ">=  is not a pin → empty version")
	require.Equal(t, "", got["flask"], "no version spec → empty")
	require.Equal(t, "", got["requests"])
	require.NotContains(t, got, "-r")
	require.Len(t, got, 4)
}

func TestRequirementsTxtSkipsURLsAndOptions(t *testing.T) {
	got := parseRequirementsTxt([]byte(`
--index-url https://example.com/pypi
-e .
git+https://github.com/foo/bar
django==4.2
`))
	require.Len(t, got, 1)
	require.Contains(t, got, "django")
}

func TestRequirementsTxtHandlesExtras(t *testing.T) {
	got := parseRequirementsTxt([]byte(`requests[socks]==2.31.0`))
	require.Equal(t, "2.31.0", got["requests"])
}

// ── pyproject.toml (PEP 621) ───────────────────────────────────

func TestPyprojectTOMLPEP621(t *testing.T) {
	got := parsePyprojectTOML([]byte(`[project]
name = "myapp"
version = "0.1.0"
dependencies = [
    "django>=4.2",
    "psycopg2-binary",
    "requests==2.31.0"
]
`))
	require.Contains(t, got, "django")
	require.Contains(t, got, "psycopg2-binary")
	require.Equal(t, "2.31.0", got["requests"])
}

func TestPyprojectTOMLPoetry(t *testing.T) {
	got := parsePyprojectTOML([]byte(`[tool.poetry]
name = "myapp"

[tool.poetry.dependencies]
python = "^3.10"
django = "^4.2"
psycopg2-binary = "^2.9"
`))
	require.Contains(t, got, "django")
	require.Contains(t, got, "psycopg2-binary")
	require.NotContains(t, got, "python", "the 'python' magic entry must be skipped")
}

func TestRequirementsTxtAndPyprojectMergeWithoutLockfile(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"requirements.txt": "django==4.2.7\nrequests==2.31.0\n",
		"pyproject.toml":   `[project]` + "\n" + `name = "x"` + "\n" + `dependencies = ["flask>=2"]` + "\n",
	})
	det := &Pip{Resolver: stubPipResolver{}}
	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 3)
	for _, d := range deps {
		require.True(t, d.Direct)
		require.NotEmpty(t, d.Notes, "missing-lockfile warning expected")
	}
}

// ── SitePackagesResolver + METADATA extraction ─────────────────

func TestSitePackagesResolverReadsLicenseHeader(t *testing.T) {
	project := t.TempDir()
	siteDir := filepath.Join(project, ".venv", "lib", "python3.11", "site-packages")
	distDir := filepath.Join(siteDir, "django-4.2.7.dist-info")
	require.NoError(t, os.MkdirAll(distDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(distDir, "METADATA"),
		[]byte("Metadata-Version: 2.1\nName: django\nVersion: 4.2.7\nLicense: BSD-3-Clause\n"),
		0o644))

	r := &SitePackagesResolver{ProjectRoot: project}
	spdx, source := r.Resolve("django", "4.2.7")
	require.Equal(t, "BSD-3-Clause", spdx)
	require.Contains(t, source, "METADATA")
}

func TestSitePackagesResolverPrefersLicenseExpression(t *testing.T) {
	project := t.TempDir()
	siteDir := filepath.Join(project, ".venv", "lib", "python3.12", "site-packages")
	distDir := filepath.Join(siteDir, "modernpkg-1.0.0.dist-info")
	require.NoError(t, os.MkdirAll(distDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(distDir, "METADATA"),
		[]byte("Metadata-Version: 2.4\nName: modernpkg\nLicense-Expression: MIT\nLicense: see LICENSE.txt\n"),
		0o644))

	r := &SitePackagesResolver{ProjectRoot: project}
	spdx, _ := r.Resolve("modernpkg", "1.0.0")
	require.Equal(t, "MIT", spdx, "License-Expression must be preferred over the legacy License header")
}

func TestSitePackagesResolverFallsBackToClassifier(t *testing.T) {
	project := t.TempDir()
	siteDir := filepath.Join(project, ".venv", "lib", "python3.11", "site-packages")
	distDir := filepath.Join(siteDir, "oldpkg-1.0.0.dist-info")
	require.NoError(t, os.MkdirAll(distDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(distDir, "METADATA"),
		[]byte("Metadata-Version: 2.1\nName: oldpkg\nLicense: UNKNOWN\nClassifier: License :: OSI Approved :: Apache Software License\n"),
		0o644))

	r := &SitePackagesResolver{ProjectRoot: project}
	spdx, _ := r.Resolve("oldpkg", "1.0.0")
	require.Equal(t, "Apache-2.0", spdx)
}

func TestSitePackagesResolverHandlesNormalisedNames(t *testing.T) {
	// PEP 503 says "PSycoPG2_Binary" and "psycopg2-binary" must collide.
	project := t.TempDir()
	siteDir := filepath.Join(project, "venv", "lib", "python3.11", "site-packages")
	distDir := filepath.Join(siteDir, "psycopg2_binary-2.9.9.dist-info")
	require.NoError(t, os.MkdirAll(distDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(distDir, "METADATA"),
		[]byte("Name: psycopg2-binary\nLicense: LGPL-3.0\n"),
		0o644))

	r := &SitePackagesResolver{ProjectRoot: project}
	spdx, _ := r.Resolve("PSycoPG2_Binary", "2.9.9")
	require.Equal(t, "LGPL-3.0", spdx)
}

func TestSitePackagesResolverHandlesEmptyInputs(t *testing.T) {
	r := &SitePackagesResolver{}
	spdx, _ := r.Resolve("x", "1.0")
	require.Equal(t, "", spdx)
	r2 := &SitePackagesResolver{ProjectRoot: t.TempDir()}
	spdx, _ = r2.Resolve("", "1.0")
	require.Equal(t, "", spdx)
}

func TestExtractLicenseFromPEP621MetadataLicenseHeader(t *testing.T) {
	meta := "Name: foo\nLicense: Apache-2.0\n"
	require.Equal(t, "Apache-2.0", extractLicenseFromPEP621Metadata([]byte(meta)))
}

func TestExtractLicenseFromPEP621MetadataUnknownTreatedAsAbsent(t *testing.T) {
	meta := "Name: foo\nLicense: UNKNOWN\n"
	require.Equal(t, "", extractLicenseFromPEP621Metadata([]byte(meta)))
}

func TestMapClassifierToSPDX(t *testing.T) {
	cases := map[string]string{
		"Classifier: License :: OSI Approved :: MIT License":                              "MIT",
		"Classifier: License :: OSI Approved :: Apache Software License":                  "Apache-2.0",
		"Classifier: License :: OSI Approved :: BSD License":                              "BSD-3-Clause",
		"Classifier: License :: OSI Approved :: GNU General Public License v3 (GPLv3)":    "GPL-3.0",
		"Classifier: License :: OSI Approved :: GNU Affero General Public License v3 (AGPLv3)": "AGPL-3.0",
		"Classifier: License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)":     "MPL-2.0",
	}
	for input, want := range cases {
		require.Equal(t, want, mapClassifierToSPDX(input), "for %q", input)
	}
}

func TestMapClassifierToSPDXUnknownReturnsEmpty(t *testing.T) {
	require.Equal(t, "", mapClassifierToSPDX("Classifier: License :: Public Domain"))
}

// ── normalisePyName ────────────────────────────────────────────

func TestNormalisePyName(t *testing.T) {
	require.Equal(t, "django", normalisePyName("Django"))
	require.Equal(t, "psycopg2-binary", normalisePyName("psycopg2_binary"))
	require.Equal(t, "psycopg2-binary", normalisePyName("PSycoPG2.binary"))
	require.Equal(t, "foo-bar", normalisePyName("foo___bar"))
}
