package format

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestBuildPURLGoMod(t *testing.T) {
	dep := scanner.Dependency{
		Name: "github.com/spf13/cobra", Version: "v1.10.2", Ecosystem: "gomod",
	}
	require.Equal(t, "pkg:golang/github.com/spf13/cobra@v1.10.2", BuildPURL(dep))
}

func TestBuildPURLNpmUnscoped(t *testing.T) {
	dep := scanner.Dependency{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"}
	require.Equal(t, "pkg:npm/lodash@4.17.21", BuildPURL(dep))
}

func TestBuildPURLNpmScoped(t *testing.T) {
	dep := scanner.Dependency{Name: "@babel/core", Version: "7.23.0", Ecosystem: "npm"}
	require.Equal(t, "pkg:npm/@babel/core@7.23.0", BuildPURL(dep))
}

func TestBuildPURLComposer(t *testing.T) {
	dep := scanner.Dependency{Name: "symfony/console", Version: "6.4.0", Ecosystem: "composer"}
	require.Equal(t, "pkg:composer/symfony/console@6.4.0", BuildPURL(dep))
}

func TestBuildPURLComposerWithoutVendor(t *testing.T) {
	// Some legacy composer packages have no vendor — should still produce a valid PURL.
	dep := scanner.Dependency{Name: "phpunit", Version: "9.0.0", Ecosystem: "composer"}
	require.Equal(t, "pkg:composer/phpunit@9.0.0", BuildPURL(dep))
}

func TestBuildPURLMaven(t *testing.T) {
	dep := scanner.Dependency{Name: "org.springframework:spring-core", Version: "6.0.0", Ecosystem: "maven"}
	require.Equal(t, "pkg:maven/org.springframework/spring-core@6.0.0", BuildPURL(dep))
}

func TestBuildPURLPip(t *testing.T) {
	dep := scanner.Dependency{Name: "django", Version: "4.2.7", Ecosystem: "pip"}
	require.Equal(t, "pkg:pypi/django@4.2.7", BuildPURL(dep))
}

func TestBuildPURLGem(t *testing.T) {
	dep := scanner.Dependency{Name: "rails", Version: "7.1.0", Ecosystem: "gem"}
	require.Equal(t, "pkg:gem/rails@7.1.0", BuildPURL(dep))
}

func TestBuildPURLCargo(t *testing.T) {
	dep := scanner.Dependency{Name: "serde", Version: "1.0.190", Ecosystem: "cargo"}
	require.Equal(t, "pkg:cargo/serde@1.0.190", BuildPURL(dep))
}

func TestBuildPURLWithoutVersion(t *testing.T) {
	// Some manifests don't pin versions — PURL omits @version.
	dep := scanner.Dependency{Name: "lodash", Ecosystem: "npm"}
	require.Equal(t, "pkg:npm/lodash", BuildPURL(dep))
}

func TestBuildPURLEmptyNameReturnsEmpty(t *testing.T) {
	require.Equal(t, "", BuildPURL(scanner.Dependency{Ecosystem: "npm"}))
}

func TestBuildPURLUnknownEcosystemReturnsEmpty(t *testing.T) {
	require.Equal(t, "", BuildPURL(scanner.Dependency{Name: "x", Ecosystem: "unknown-pm"}))
}

func TestSplitNamespaceNpmScoped(t *testing.T) {
	ns, name := splitNamespace("npm", "@babel/core")
	require.Equal(t, "@babel", ns)
	require.Equal(t, "core", name)
}

func TestSplitNamespaceNpmUnscoped(t *testing.T) {
	ns, name := splitNamespace("npm", "lodash")
	require.Equal(t, "", ns)
	require.Equal(t, "lodash", name)
}

func TestSplitNamespaceComposer(t *testing.T) {
	ns, name := splitNamespace("composer", "vendor/package")
	require.Equal(t, "vendor", ns)
	require.Equal(t, "package", name)
}

func TestSplitNamespaceMavenColon(t *testing.T) {
	ns, name := splitNamespace("maven", "org.example:my-artifact")
	require.Equal(t, "org.example", ns)
	require.Equal(t, "my-artifact", name)
}

func TestSplitNamespaceGoModKeepsFullPath(t *testing.T) {
	// Golang PURL spec: no namespace split — full module path stays as name.
	ns, name := splitNamespace("gomod", "github.com/foo/bar")
	require.Equal(t, "", ns)
	require.Equal(t, "github.com/foo/bar", name)
}

func TestSplitNamespacePipNoNamespace(t *testing.T) {
	ns, name := splitNamespace("pip", "django")
	require.Equal(t, "", ns)
	require.Equal(t, "django", name)
}
