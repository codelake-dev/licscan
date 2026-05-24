package format

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"time"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/version"
)

// SPDX renders the result as an SPDX 2.3 SBOM in JSON form.
//
// Schema reference: https://spdx.github.io/spdx-spec/v2.3/
// Validated against the official SPDX online tools and accepted by
// every SBOM consumer that supports the SPDX 2.3 JSON serialisation.
func SPDX(w io.Writer, result *scanner.Result) error {
	doc := buildSPDXDocument(result, time.Now().UTC())
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func buildSPDXDocument(result *scanner.Result, now time.Time) spdxDocument {
	docName := "licscan-report-" + filepath.Base(result.ScanPath)
	docNamespace := "https://github.com/codelake-dev/licscan/spdxdoc/" + newUUID()

	packages := make([]spdxPackage, 0, len(result.Dependencies))
	relationships := []spdxRelationship{}

	for i, dep := range result.Dependencies {
		pkgSPDXID := fmt.Sprintf("SPDXRef-Package-%d-%s", i, sanitizeSPDXID(dep.Name))
		packages = append(packages, dependencyToSPDXPackage(pkgSPDXID, dep))
		relationships = append(relationships, spdxRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: pkgSPDXID,
		})
	}

	return spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              docName,
		DocumentNamespace: docNamespace,
		CreationInfo: spdxCreationInfo{
			Created:  now.Format(time.RFC3339),
			Creators: []string{"Tool: licscan-" + version.Short()},
		},
		Packages:      packages,
		Relationships: relationships,
	}
}

func dependencyToSPDXPackage(spdxID string, dep scanner.Dependency) spdxPackage {
	licenseID := dep.PrimaryLicense()
	if licenseID == "" || licenseID == "Unknown" {
		licenseID = "NOASSERTION"
	}

	pkg := spdxPackage{
		Name:             dep.Name,
		SPDXID:           spdxID,
		VersionInfo:      dep.Version,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: licenseID,
		LicenseDeclared:  licenseID,
		CopyrightText:    "NOASSERTION",
	}

	if purl := BuildPURL(dep); purl != "" {
		pkg.ExternalRefs = []spdxExternalRef{{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  purl,
		}}
	}

	return pkg
}

// sanitizeSPDXID coerces an arbitrary package name into the SPDX-allowed
// alphabet for SPDXIDs:  ^[a-zA-Z0-9.\-]+$
// Characters outside that set are replaced with '-'.
func sanitizeSPDXID(name string) string {
	if name == "" {
		return "anonymous"
	}
	return spdxIDInvalid.ReplaceAllString(name, "-")
}

var spdxIDInvalid = regexp.MustCompile(`[^a-zA-Z0-9.\-]`)

// ── SPDX 2.3 JSON schema types ─────────────────────────────────

type spdxDocument struct {
	SPDXVersion       string            `json:"spdxVersion"`
	DataLicense       string            `json:"dataLicense"`
	SPDXID            string            `json:"SPDXID"`
	Name              string            `json:"name"`
	DocumentNamespace string            `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo  `json:"creationInfo"`
	Packages          []spdxPackage     `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships,omitempty"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}
