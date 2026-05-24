package format

import (
	"strings"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// BuildPURL converts a Dependency into a Package URL per the spec at
// https://github.com/package-url/purl-spec.
//
// Format: pkg:<type>/[<namespace>/]<name>@<version>
//
// Returns an empty string for dependencies without enough information to
// build a valid PURL — callers should treat that as "no PURL available"
// rather than emitting a malformed one.
func BuildPURL(dep scanner.Dependency) string {
	if dep.Name == "" {
		return ""
	}

	purlType, ok := ecosystemToPURLType[dep.Ecosystem]
	if !ok {
		return ""
	}

	namespace, name := splitNamespace(dep.Ecosystem, dep.Name)
	purl := "pkg:" + purlType + "/"
	if namespace != "" {
		purl += namespace + "/"
	}
	purl += name

	if dep.Version != "" {
		purl += "@" + dep.Version
	}
	return purl
}

// ecosystemToPURLType maps our internal ecosystem identifiers to the
// PURL `type` component as defined in the spec.
var ecosystemToPURLType = map[string]string{
	"gomod":    "golang",
	"npm":      "npm",
	"composer": "composer",
	"pip":      "pypi",
	"gem":      "gem",
	"cargo":    "cargo",
	"maven":    "maven",
}

// splitNamespace separates a package identifier into (namespace, name)
// per ecosystem conventions:
//   - npm:      "@scope/pkg" → "@scope", "pkg"; otherwise "", "pkg"
//   - composer: "vendor/pkg" → "vendor", "pkg"
//   - maven:    "groupId:artifactId" → "groupId", "artifactId"
//   - golang:   no namespace split — full module path stays as name
//               (per PURL golang spec)
//   - others:   no namespace
func splitNamespace(ecosystem, pkgName string) (namespace, name string) {
	switch ecosystem {
	case "npm":
		// Scoped: "@scope/pkg" → namespace="@scope", name="pkg".
		if strings.HasPrefix(pkgName, "@") {
			if idx := strings.Index(pkgName, "/"); idx > 0 {
				return pkgName[:idx], pkgName[idx+1:]
			}
		}
		return "", pkgName
	case "composer":
		if idx := strings.Index(pkgName, "/"); idx > 0 {
			return pkgName[:idx], pkgName[idx+1:]
		}
		return "", pkgName
	case "maven":
		if idx := strings.Index(pkgName, ":"); idx > 0 {
			return pkgName[:idx], pkgName[idx+1:]
		}
		return "", pkgName
	default:
		return "", pkgName
	}
}
