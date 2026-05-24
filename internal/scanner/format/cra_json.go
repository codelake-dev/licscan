package format

import (
	"encoding/json"
	"io"
	"time"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/scanner/policy"
	"github.com/codelake-dev/licscan/internal/version"
)

// CRAManifest holds the manufacturer + product metadata required by
// EU CRA Article 13 evidence. Loaded from .licscan.yml via the policy
// package; the CRA exporters embed these fields into both the JSON
// SBOM and the PDF cover page.
type CRAManifest struct {
	Manufacturer policy.Manufacturer
	Product      policy.Product
}

// CRAJSON renders an EU CRA-compliant CycloneDX 1.5 SBOM.
//
// Strict superset of the regular CycloneDX output — additional fields:
//   - metadata.manufacturer    (CRA Art. 13(2): producer identity)
//   - metadata.supplier        (always = licscan tool)
//   - metadata.lifecycles      (CRA evidence covers the 'operations' phase)
//   - metadata.component       (the scanned product itself, with supplier,
//     releaseNotes carrying the support window)
//   - metadata.properties[]    (free-form key/value: CRA Article reference,
//     manufacturer country, product category)
//
// Schema: https://cyclonedx.org/docs/1.5/json/
// CRA reference: Regulation (EU) 2024/2847 Art. 13 + Annex I §1(2)(s).
func CRAJSON(w io.Writer, result *scanner.Result, manifest CRAManifest) error {
	bom := buildCRABOM(result, manifest, time.Now().UTC())
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(bom)
}

func buildCRABOM(result *scanner.Result, manifest CRAManifest, now time.Time) craBOM {
	// Re-use the standard CycloneDX component conversion for the deps list.
	components := make([]cycloneDXComponent, 0, len(result.Dependencies))
	for _, dep := range result.Dependencies {
		components = append(components, dependencyToCycloneDXComponent(dep))
	}

	return craBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + newUUID(),
		Version:      1,
		Metadata: craMetadata{
			Timestamp:    now.Format(time.RFC3339),
			Tools:        []cycloneDXTool{licscanTool()},
			Manufacturer: manufacturerNode(manifest.Manufacturer),
			Supplier:     supplierNode(),
			Component:    projectComponent(result, manifest),
			Lifecycles: []craLifecycle{
				{Phase: "operations"},
			},
			Properties: craProperties(manifest),
		},
		Components: components,
	}
}

func licscanTool() cycloneDXTool {
	return cycloneDXTool{
		Vendor:  "codelake Technologies LLC",
		Name:    "licscan",
		Version: version.Short(),
	}
}

func manufacturerNode(m policy.Manufacturer) *craOrgEntity {
	if m.IsZero() {
		return nil
	}
	node := &craOrgEntity{Name: orValue(m.Name, "NOASSERTION")}
	if m.URL != "" {
		node.URL = []string{m.URL}
	}
	if m.Email != "" {
		node.Contacts = []craContact{{Email: m.Email}}
	}
	return node
}

func supplierNode() *craOrgEntity {
	// The supplier of the SBOM is licscan itself, not the manufacturer.
	// Per CycloneDX 1.5 metadata.supplier is "the organization that
	// supplied the component or BOM".
	return &craOrgEntity{
		Name: "codelake Technologies LLC",
		URL:  []string{"https://github.com/codelake-dev/licscan"},
	}
}

func projectComponent(result *scanner.Result, manifest CRAManifest) cycloneDXComponent {
	name := manifest.Product.Name
	if name == "" {
		name = basenameOrEmpty(result.ScanPath)
	}
	comp := cycloneDXComponent{
		Type:    "application",
		BOMRef:  "licscan-scan-target",
		Name:    orValue(name, "NOASSERTION"),
		Version: orValue(manifest.Product.Version, "0.0.0"),
	}
	return comp
}

func craProperties(manifest CRAManifest) []craProperty {
	props := []craProperty{
		{Name: "eu-cra:article", Value: "13"},
		{Name: "eu-cra:annex", Value: "I §1(2)(s)"},
		{Name: "eu-cra:regulation", Value: "Regulation (EU) 2024/2847"},
	}
	if manifest.Manufacturer.Country != "" {
		props = append(props, craProperty{
			Name: "eu-cra:manufacturer-country", Value: manifest.Manufacturer.Country,
		})
	}
	if manifest.Product.Category != "" {
		props = append(props, craProperty{
			Name: "eu-cra:product-category", Value: manifest.Product.Category,
		})
	}
	if manifest.Product.SupportLifecycleEnd != "" {
		props = append(props, craProperty{
			Name: "eu-cra:support-lifecycle-end", Value: manifest.Product.SupportLifecycleEnd,
		})
	}
	return props
}

// orValue returns first if non-empty, else fallback. Used to surface
// NOASSERTION instead of empty strings per CycloneDX/SPDX conventions.
func orValue(first, fallback string) string {
	if first != "" {
		return first
	}
	return fallback
}

func basenameOrEmpty(path string) string {
	// We deliberately avoid filepath.Base here to keep this file
	// import-light — callers always pass an absolute path produced
	// upstream by filepath.Abs, so a simple last-slash split is enough.
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}

// ── CRA-extended CycloneDX schema (extends the base types) ─────

type craBOM struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber"`
	Version      int                  `json:"version"`
	Metadata     craMetadata          `json:"metadata"`
	Components   []cycloneDXComponent `json:"components"`
}

type craMetadata struct {
	Timestamp    string             `json:"timestamp"`
	Tools        []cycloneDXTool    `json:"tools"`
	Manufacturer *craOrgEntity      `json:"manufacturer,omitempty"`
	Supplier     *craOrgEntity      `json:"supplier,omitempty"`
	Component    cycloneDXComponent `json:"component"`
	Lifecycles   []craLifecycle     `json:"lifecycles,omitempty"`
	Properties   []craProperty      `json:"properties,omitempty"`
}

// craOrgEntity matches CycloneDX 1.5 "organizationalEntity" schema.
type craOrgEntity struct {
	Name     string       `json:"name,omitempty"`
	URL      []string     `json:"url,omitempty"`
	Contacts []craContact `json:"contact,omitempty"`
}

type craContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type craLifecycle struct {
	Phase string `json:"phase"`
}

type craProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
