package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

type stubMavenResolver struct {
	results map[string]struct{ spdx, source string }
}

func (s stubMavenResolver) Resolve(group, artifact, _ string) (string, string) {
	if r, ok := s.results[group+":"+artifact]; ok {
		return r.spdx, r.source
	}
	return "", ""
}

// ── basic detection ────────────────────────────────────────────

func TestMavenName(t *testing.T) {
	require.Equal(t, "maven", (&Maven{}).Name())
}

func TestMavenReturnsNotFoundWhenNoPomXML(t *testing.T) {
	found, deps, err := (&Maven{}).Detect(t.TempDir())
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, deps)
}

func TestMavenErrorsOnMalformedPomXML(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pom.xml": "<this is><not valid xml>",
	})
	_, _, err := (&Maven{}).Detect(dir)
	require.Error(t, err)
}

// ── pom.xml parsing ────────────────────────────────────────────

const samplePom = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.0.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
`

func TestMavenParsesAllDependencies(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pom.xml": samplePom,
	})
	det := &Maven{Resolver: stubMavenResolver{}}
	found, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, deps, 3)
}

func TestMavenCoordinateIsGroupArtifactPair(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pom.xml": samplePom,
	})
	det := &Maven{Resolver: stubMavenResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	names := map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
	}
	require.True(t, names["org.springframework:spring-core"])
	require.True(t, names["com.google.guava:guava"])
	require.True(t, names["junit:junit"])
}

func TestMavenMarksAllAsDirect(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pom.xml": samplePom,
	})
	det := &Maven{Resolver: stubMavenResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	for _, d := range deps {
		require.True(t, d.Direct, "every pom.xml entry is direct in V1 (no transitive resolution)")
	}
}

func TestMavenUsesResolverForLicenses(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pom.xml": samplePom,
	})
	det := &Maven{Resolver: stubMavenResolver{results: map[string]struct{ spdx, source string }{
		"org.springframework:spring-core": {"Apache-2.0", "stub"},
		"com.google.guava:guava":          {"Apache-2.0", "stub"},
		"junit:junit":                     {"EPL-1.0", "stub"},
	}}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)

	byName := map[string]scanner.Dependency{}
	for _, d := range deps {
		byName[d.Name] = d
	}
	require.Equal(t, "Apache-2.0", byName["org.springframework:spring-core"].PrimaryLicense())
	require.Equal(t, "EPL-1.0", byName["junit:junit"].PrimaryLicense())
	require.Equal(t, scanner.RiskWeakCopyleft, byName["junit:junit"].PrimaryRisk())
}

func TestMavenMarksUnresolvedAsUnknown(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pom.xml": samplePom,
	})
	det := &Maven{Resolver: stubMavenResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)
	for _, d := range deps {
		require.Equal(t, "Unknown", d.PrimaryLicense())
		require.NotEmpty(t, d.Notes)
	}
}

func TestMavenSkipsDependenciesWithoutGroupOrArtifact(t *testing.T) {
	pom := `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>x</groupId><artifactId>x</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>ok</groupId><artifactId>ok</artifactId><version>1</version></dependency>
    <dependency><artifactId>missing-group</artifactId><version>1</version></dependency>
    <dependency><groupId>missing-artifact</groupId><version>1</version></dependency>
  </dependencies>
</project>
`
	dir := writeProject(t, map[string]string{"pom.xml": pom})
	det := &Maven{Resolver: stubMavenResolver{}}
	_, deps, err := det.Detect(dir)
	require.NoError(t, err)
	require.Len(t, deps, 1, "incomplete coordinates must be dropped")
	require.Equal(t, "ok:ok", deps[0].Name)
}

// ── M2Resolver ─────────────────────────────────────────────────

func TestM2ResolverReadsLicenseFromPom(t *testing.T) {
	repo := t.TempDir()
	pomDir := filepath.Join(repo, "org", "springframework", "spring-core", "6.0.0")
	require.NoError(t, os.MkdirAll(pomDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(pomDir, "spring-core-6.0.0.pom"),
		[]byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>org.springframework</groupId>
  <artifactId>spring-core</artifactId>
  <version>6.0.0</version>
  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
      <url>https://www.apache.org/licenses/LICENSE-2.0</url>
    </license>
  </licenses>
</project>
`),
		0o644))

	r := &M2Resolver{RepoRoot: repo}
	spdx, source := r.Resolve("org.springframework", "spring-core", "6.0.0")
	require.Equal(t, "Apache-2.0", spdx)
	require.Contains(t, source, "spring-core-6.0.0.pom")
}

func TestM2ResolverHandlesMissingDep(t *testing.T) {
	r := &M2Resolver{RepoRoot: t.TempDir()}
	spdx, source := r.Resolve("org.example", "nope", "1.0")
	require.Equal(t, "", spdx)
	require.Equal(t, "", source)
}

func TestM2ResolverHandlesEmptyInputs(t *testing.T) {
	r := &M2Resolver{RepoRoot: ""}
	spdx, _ := r.Resolve("x", "y", "1.0")
	require.Equal(t, "", spdx)

	r2 := &M2Resolver{RepoRoot: t.TempDir()}
	spdx, _ = r2.Resolve("", "y", "1.0")
	require.Equal(t, "", spdx)
}

func TestDefaultM2RepoHonoursEnv(t *testing.T) {
	t.Setenv("MAVEN_REPO", "/custom/m2/repo")
	require.Equal(t, "/custom/m2/repo", defaultM2Repo())
}

// ── License-name → SPDX mapping ────────────────────────────────

func TestMapMavenLicenseToSPDXCoversCommonCases(t *testing.T) {
	cases := []struct {
		name, url string
		want      string
	}{
		{"Apache License, Version 2.0", "", "Apache-2.0"},
		{"The Apache License, Version 2.0", "", "Apache-2.0"},
		{"The Apache Software License, Version 2.0", "https://www.apache.org/licenses/LICENSE-2.0.txt", "Apache-2.0"},
		{"MIT License", "", "MIT"},
		{"The MIT License", "", "MIT"},
		{"MIT", "", "MIT"},
		{"BSD 3-Clause License", "", "BSD-3-Clause"},
		{"The New BSD License", "", "BSD-3-Clause"},
		{"BSD License", "", "BSD-3-Clause"},
		{"BSD 2-Clause License", "", "BSD-2-Clause"},
		{"ISC License", "", "ISC"},
		{"Eclipse Public License - v 1.0", "", "EPL-1.0"},
		{"Eclipse Public License 2.0", "", "EPL-2.0"},
		{"Mozilla Public License 2.0", "", "MPL-2.0"},
		{"GNU Lesser General Public License, Version 2.1", "", "LGPL-2.1"},
		{"GNU General Public License (GPL), Version 3", "", "GPL-3.0"},
		{"GNU General Public License v2.0", "", "GPL-2.0"},
		{"GNU Affero General Public License v3.0", "", "AGPL-3.0"},
		{"Common Development and Distribution License (CDDL) v1.1", "", "CDDL-1.1"},
		{"Common Development and Distribution License (CDDL) v1.0", "", "CDDL-1.0"},
		{"The Unlicense", "", "Unlicense"},
		{"Creative Commons CC0", "", "CC0-1.0"},
		{"Public Domain", "", "CC0-1.0"},
	}
	for _, c := range cases {
		got := mapMavenLicenseToSPDX(c.name, c.url)
		require.Equal(t, c.want, got, "for name=%q url=%q", c.name, c.url)
	}
}

func TestMapMavenLicenseToSPDXReturnsEmptyForUnknown(t *testing.T) {
	require.Equal(t, "", mapMavenLicenseToSPDX("My Custom Corporate License v0.1", ""))
}
