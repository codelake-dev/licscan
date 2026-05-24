package format

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestSPDXProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, sampleResult()))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
}

func TestSPDXHasRequiredTopLevelFields(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, sampleResult()))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	require.Equal(t, "SPDX-2.3", doc.SPDXVersion)
	require.Equal(t, "CC0-1.0", doc.DataLicense, "SPDX docs themselves must be CC0-1.0 licensed per spec")
	require.Equal(t, "SPDXRef-DOCUMENT", doc.SPDXID)
	require.NotEmpty(t, doc.Name)
	require.NotEmpty(t, doc.DocumentNamespace)
}

func TestSPDXDocumentNamespaceIsValidURI(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, sampleResult()))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	require.True(t, strings.HasPrefix(doc.DocumentNamespace, "https://"),
		"namespace must be a fully qualified URI per SPDX spec")
}

func TestSPDXCreationInfoIncludesLicscanTool(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, sampleResult()))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	require.NotEmpty(t, doc.CreationInfo.Created)
	require.NotEmpty(t, doc.CreationInfo.Creators)
	hasLicscan := false
	for _, c := range doc.CreationInfo.Creators {
		if strings.HasPrefix(c, "Tool: licscan") {
			hasLicscan = true
		}
	}
	require.True(t, hasLicscan, "creators must include 'Tool: licscan-...'")
}

func TestSPDXPackagesCountMatchesDependencies(t *testing.T) {
	result := sampleResult()

	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, result))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	require.Len(t, doc.Packages, len(result.Dependencies))
}

func TestSPDXPackageEachHasRequiredFields(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, sampleResult()))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	for _, p := range doc.Packages {
		require.NotEmpty(t, p.Name, "every package must have a name")
		require.NotEmpty(t, p.SPDXID, "every package must have an SPDXID")
		require.Equal(t, "NOASSERTION", p.DownloadLocation,
			"downloadLocation must be NOASSERTION when not crawled")
		require.False(t, p.FilesAnalyzed, "filesAnalyzed=false (we don't extract file-level data)")
	}
}

func TestSPDXPackageSPDXIDsMatchSpecRegex(t *testing.T) {
	// SPDXID must match ^SPDXRef-[a-zA-Z0-9.\-]+$
	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, sampleResult()))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	idPattern := regexp.MustCompile(`^SPDXRef-[a-zA-Z0-9.\-]+$`)
	for _, p := range doc.Packages {
		require.True(t, idPattern.MatchString(p.SPDXID),
			"SPDXID %q must match SPDX spec regex", p.SPDXID)
	}
}

func TestSPDXEmitsLicenseConcludedAndDeclared(t *testing.T) {
	r := scanner.NewResult("/project")
	r.Add(scanner.Dependency{
		Name: "lib", Version: "1.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
	})

	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, r))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	require.Equal(t, "MIT", doc.Packages[0].LicenseConcluded)
	require.Equal(t, "MIT", doc.Packages[0].LicenseDeclared)
}

func TestSPDXEmitsNOASSERTIONForUnknownLicense(t *testing.T) {
	r := scanner.NewResult("/project")
	r.Add(scanner.Dependency{
		Name: "mystery", Version: "1.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense("Unknown", "")},
	})

	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, r))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	require.Equal(t, "NOASSERTION", doc.Packages[0].LicenseConcluded)
	require.Equal(t, "NOASSERTION", doc.Packages[0].LicenseDeclared)
}

func TestSPDXEmitsPURLAsExternalRef(t *testing.T) {
	r := scanner.NewResult("/project")
	r.Add(scanner.Dependency{
		Name: "github.com/spf13/cobra", Version: "v1.10.2", Ecosystem: "gomod",
		Licenses: []scanner.License{scanner.NewLicense("Apache-2.0", "")},
	})

	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, r))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	require.Len(t, doc.Packages[0].ExternalRefs, 1)
	require.Equal(t, "PACKAGE-MANAGER", doc.Packages[0].ExternalRefs[0].ReferenceCategory)
	require.Equal(t, "purl", doc.Packages[0].ExternalRefs[0].ReferenceType)
	require.Equal(t, "pkg:golang/github.com/spf13/cobra@v1.10.2",
		doc.Packages[0].ExternalRefs[0].ReferenceLocator)
}

func TestSPDXRelationshipsDescribeEveryPackage(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, sampleResult()))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	require.Len(t, doc.Relationships, len(doc.Packages),
		"every package must have a DESCRIBES relationship from the document")

	for _, rel := range doc.Relationships {
		require.Equal(t, "SPDXRef-DOCUMENT", rel.SPDXElementID)
		require.Equal(t, "DESCRIBES", rel.RelationshipType)
		require.True(t, strings.HasPrefix(rel.RelatedSPDXElement, "SPDXRef-Package-"),
			"DESCRIBES must point to a package SPDXID, got %s", rel.RelatedSPDXElement)
	}
}

func TestSPDXHandlesEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, scanner.NewResult("/empty")))

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	require.Equal(t, "SPDX-2.3", doc.SPDXVersion)
	require.Empty(t, doc.Packages)
	require.Empty(t, doc.Relationships)
}

func TestSPDXIsPrettyPrinted(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SPDX(&buf, sampleResult()))
	require.Contains(t, buf.String(), "\n  ", "must be pretty-printed (indented)")
}

func TestSanitizeSPDXIDPassesAllowedChars(t *testing.T) {
	require.Equal(t, "lodash", sanitizeSPDXID("lodash"))
	require.Equal(t, "github.com-spf13-cobra", sanitizeSPDXID("github.com/spf13/cobra"))
	require.Equal(t, "-babel-core", sanitizeSPDXID("@babel/core"))
	require.Equal(t, "name.with.dots", sanitizeSPDXID("name.with.dots"))
}

func TestSanitizeSPDXIDHandlesEmpty(t *testing.T) {
	require.Equal(t, "anonymous", sanitizeSPDXID(""))
}

func TestSanitizeSPDXIDStripsSpecials(t *testing.T) {
	require.NotContains(t, sanitizeSPDXID("name with spaces"), " ")
	require.NotContains(t, sanitizeSPDXID("name(parens)"), "(")
	require.NotContains(t, sanitizeSPDXID("name@version"), "@")
}
