// Package version exposes build-time metadata injected via ldflags.
//
// During releases the values are set with -ldflags so the binary reports
// its actual version and commit. Local builds fall back to the defaults.
package version

import "fmt"

// These variables are overridden at build time via:
//
//	-ldflags "-X github.com/codelake-dev/licscan/internal/version.Version=$(git describe --tags)"
//	-ldflags "-X github.com/codelake-dev/licscan/internal/version.Commit=$(git rev-parse HEAD)"
//	-ldflags "-X github.com/codelake-dev/licscan/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// Short returns just the version string (e.g. "v1.2.3" or "dev").
func Short() string {
	if Version == "dev" {
		return Version
	}
	return "v" + Version
}

// Full returns the full version banner including commit and build date.
func Full() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Short(), Commit, BuildDate)
}
