package format

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/version"
)

// CycloneDX renders the result as a CycloneDX 1.5 SBOM in JSON form.
//
// Schema reference: https://cyclonedx.org/docs/1.5/json/
// The output is accepted by Trivy, Grype, Snyk, Dependency-Track, and
// every other tool that ingests CycloneDX 1.5.
func CycloneDX(w io.Writer, result *scanner.Result) error {
	bom := buildCycloneDXBOM(result, time.Now().UTC())
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(bom)
}

func buildCycloneDXBOM(result *scanner.Result, now time.Time) cycloneDXBOM {
	components := make([]cycloneDXComponent, 0, len(result.Dependencies))
	for _, dep := range result.Dependencies {
		components = append(components, dependencyToCycloneDXComponent(dep))
	}

	return cycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + newUUID(),
		Version:      1,
		Metadata: cycloneDXMetadata{
			Timestamp: now.Format(time.RFC3339),
			Tools: []cycloneDXTool{{
				Vendor:  "codelake Technologies LLC",
				Name:    "licscan",
				Version: version.Short(),
			}},
			Component: cycloneDXComponent{
				Type:   "application",
				BOMRef: "licscan-scan-target",
				Name:   filepath.Base(result.ScanPath),
			},
		},
		Components: components,
	}
}

func dependencyToCycloneDXComponent(dep scanner.Dependency) cycloneDXComponent {
	purl := BuildPURL(dep)
	bomRef := purl
	if bomRef == "" {
		bomRef = dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
	}

	licenses := make([]cycloneDXLicenseChoice, 0, len(dep.Licenses))
	for _, lic := range dep.Licenses {
		if lic.SPDX == "" || lic.SPDX == "Unknown" {
			// CycloneDX prefers expression "NOASSERTION" when SPDX is unknown.
			licenses = append(licenses, cycloneDXLicenseChoice{
				Expression: "NOASSERTION",
			})
			continue
		}
		licenses = append(licenses, cycloneDXLicenseChoice{
			License: &cycloneDXLicense{ID: lic.SPDX},
		})
	}

	scope := "required"
	if !dep.Direct {
		// CycloneDX scope "optional" expresses "not required for the
		// top-level component to function" — closest match for transitive.
		scope = "optional"
	}

	return cycloneDXComponent{
		Type:     "library",
		BOMRef:   bomRef,
		Name:     dep.Name,
		Version:  dep.Version,
		PURL:     purl,
		Licenses: licenses,
		Scope:    scope,
	}
}

// newUUID generates an RFC 4122 v4 UUID without pulling in google/uuid.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is exceedingly rare; fall back to a static
		// placeholder rather than panicking — the SBOM is still valid JSON.
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}

// ── CycloneDX 1.5 JSON schema types ────────────────────────────

type cycloneDXBOM struct {
	BOMFormat    string              `json:"bomFormat"`
	SpecVersion  string              `json:"specVersion"`
	SerialNumber string              `json:"serialNumber"`
	Version      int                 `json:"version"`
	Metadata     cycloneDXMetadata   `json:"metadata"`
	Components   []cycloneDXComponent `json:"components"`
}

type cycloneDXMetadata struct {
	Timestamp string             `json:"timestamp"`
	Tools     []cycloneDXTool    `json:"tools"`
	Component cycloneDXComponent `json:"component"`
}

type cycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cycloneDXComponent struct {
	Type     string                   `json:"type"`
	BOMRef   string                   `json:"bom-ref"`
	Name     string                   `json:"name"`
	Version  string                   `json:"version,omitempty"`
	PURL     string                   `json:"purl,omitempty"`
	Licenses []cycloneDXLicenseChoice `json:"licenses,omitempty"`
	Scope    string                   `json:"scope,omitempty"`
}

// cycloneDXLicenseChoice is the union-like type the spec uses:
// either {license: {id: "MIT"}} or {expression: "MIT OR Apache-2.0"}.
type cycloneDXLicenseChoice struct {
	License    *cycloneDXLicense `json:"license,omitempty"`
	Expression string            `json:"expression,omitempty"`
}

type cycloneDXLicense struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}
