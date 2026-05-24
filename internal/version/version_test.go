package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShortReturnsDevByDefault(t *testing.T) {
	t.Cleanup(restoreVars(Version, Commit, BuildDate))
	Version = "dev"
	require.Equal(t, "dev", Short())
}

func TestShortPrefixesReleaseVersionsWithV(t *testing.T) {
	t.Cleanup(restoreVars(Version, Commit, BuildDate))
	Version = "1.2.3"
	require.Equal(t, "v1.2.3", Short())
}

func TestFullIncludesAllBuildMetadata(t *testing.T) {
	t.Cleanup(restoreVars(Version, Commit, BuildDate))
	Version = "1.0.0"
	Commit = "abc1234"
	BuildDate = "2026-05-24T12:00:00Z"

	full := Full()
	require.True(t, strings.Contains(full, "v1.0.0"), "version: %s", full)
	require.True(t, strings.Contains(full, "abc1234"), "commit: %s", full)
	require.True(t, strings.Contains(full, "2026-05-24T12:00:00Z"), "date: %s", full)
}

func restoreVars(v, c, b string) func() {
	return func() {
		Version = v
		Commit = c
		BuildDate = b
	}
}
