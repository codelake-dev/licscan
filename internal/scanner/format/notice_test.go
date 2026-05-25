package format

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestNoticeContainsHeader(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Notice(&buf, sampleResult(), "acme-api"))

	out := buf.String()
	assert.Contains(t, out, "THIRD-PARTY SOFTWARE NOTICES")
	assert.Contains(t, out, "acme-api")
	assert.Contains(t, out, "3 dependencies")
}

func TestNoticeListsAllDeps(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Notice(&buf, sampleResult(), ""))

	out := buf.String()
	assert.Contains(t, out, "lib-mit")
	assert.Contains(t, out, "lib-gpl")
	assert.Contains(t, out, "lib-agpl")
}

func TestNoticeShowsLicenses(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Notice(&buf, sampleResult(), ""))

	out := buf.String()
	assert.Contains(t, out, "License: MIT")
	assert.Contains(t, out, "License: GPL-3.0")
	assert.Contains(t, out, "License: AGPL-3.0")
}

func TestNoticeSortsByEcosystemThenName(t *testing.T) {
	r := scanner.NewResult("/test")
	r.Add(scanner.Dependency{
		Name: "z-lib", Version: "1.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
	})
	r.Add(scanner.Dependency{
		Name: "a-lib", Version: "1.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
	})
	r.Add(scanner.Dependency{
		Name: "m-lib", Version: "1.0", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
	})

	var buf bytes.Buffer
	require.NoError(t, Notice(&buf, r, ""))

	out := buf.String()
	posGomod := strings.Index(out, "m-lib")
	posA := strings.Index(out, "a-lib")
	posZ := strings.Index(out, "z-lib")

	assert.Less(t, posGomod, posA, "gomod deps should come before npm deps")
	assert.Less(t, posA, posZ, "a-lib should come before z-lib within npm")
}

func TestNoticeDefaultProjectName(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Notice(&buf, sampleResult(), ""))

	assert.Contains(t, buf.String(), "This software")
}

func TestNoticeContainsFooter(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Notice(&buf, sampleResult(), "myproject"))

	assert.Contains(t, buf.String(), "End of THIRD-PARTY SOFTWARE NOTICES for myproject.")
}

func TestNoticeHandlesEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Notice(&buf, scanner.NewResult("/empty"), "test"))

	out := buf.String()
	assert.Contains(t, out, "0 dependencies")
	assert.Contains(t, out, "End of THIRD-PARTY SOFTWARE NOTICES")
}
