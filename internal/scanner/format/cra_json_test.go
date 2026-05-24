package format

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner/policy"
)

func sampleManifest() CRAManifest {
	return CRAManifest{
		Manufacturer: policy.Manufacturer{
			Name:    "Acme GmbH",
			Email:   "security@acme.example",
			URL:     "https://acme.example",
			Country: "DE",
		},
		Product: policy.Product{
			Name:                "my-app",
			Version:             "1.2.3",
			Category:            "important",
			SupportLifecycleEnd: "2031-05-24",
		},
	}
}

// ── basic schema ───────────────────────────────────────────────

func TestCRAJSONProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), sampleManifest()))
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
}

func TestCRAJSONIsCycloneDX15(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), sampleManifest()))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Equal(t, "CycloneDX", bom.BOMFormat)
	require.Equal(t, "1.5", bom.SpecVersion)
	require.NotEmpty(t, bom.SerialNumber)
}

// ── manufacturer + supplier ─────────────────────────────────────

func TestCRAJSONIncludesManufacturer(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), sampleManifest()))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))

	require.NotNil(t, bom.Metadata.Manufacturer, "manufacturer block must be present")
	require.Equal(t, "Acme GmbH", bom.Metadata.Manufacturer.Name)
	require.Contains(t, bom.Metadata.Manufacturer.URL, "https://acme.example")
	require.Len(t, bom.Metadata.Manufacturer.Contacts, 1)
	require.Equal(t, "security@acme.example", bom.Metadata.Manufacturer.Contacts[0].Email)
}

func TestCRAJSONOmitsManufacturerWhenZero(t *testing.T) {
	manifest := CRAManifest{} // empty
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), manifest))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Nil(t, bom.Metadata.Manufacturer,
		"empty manufacturer must serialise as absent, not as empty object")
}

func TestCRAJSONAlwaysIncludesSupplierAsLicscan(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), CRAManifest{}))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.NotNil(t, bom.Metadata.Supplier)
	require.Contains(t, bom.Metadata.Supplier.Name, "codelake Technologies")
}

// ── product component ───────────────────────────────────────────

func TestCRAJSONProductComponentFromManifest(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), sampleManifest()))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Equal(t, "my-app", bom.Metadata.Component.Name)
	require.Equal(t, "1.2.3", bom.Metadata.Component.Version)
	require.Equal(t, "application", bom.Metadata.Component.Type)
}

func TestCRAJSONProductComponentFallsBackToScanPathBasename(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), CRAManifest{}))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	// sampleResult uses /some/project as scan path → basename = "project"
	require.Equal(t, "project", bom.Metadata.Component.Name)
	require.Equal(t, "0.0.0", bom.Metadata.Component.Version)
}

// ── lifecycles + properties ─────────────────────────────────────

func TestCRAJSONIncludesOperationsLifecycle(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), sampleManifest()))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Len(t, bom.Metadata.Lifecycles, 1)
	require.Equal(t, "operations", bom.Metadata.Lifecycles[0].Phase)
}

func TestCRAJSONIncludesCRAArticleReference(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), sampleManifest()))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))

	propsByName := map[string]string{}
	for _, p := range bom.Metadata.Properties {
		propsByName[p.Name] = p.Value
	}
	require.Equal(t, "13", propsByName["eu-cra:article"])
	require.Equal(t, "Regulation (EU) 2024/2847", propsByName["eu-cra:regulation"])
	require.Equal(t, "I §1(2)(s)", propsByName["eu-cra:annex"])
	require.Equal(t, "DE", propsByName["eu-cra:manufacturer-country"])
	require.Equal(t, "important", propsByName["eu-cra:product-category"])
	require.Equal(t, "2031-05-24", propsByName["eu-cra:support-lifecycle-end"])
}

func TestCRAJSONOmitsOptionalPropertiesWhenManufacturerEmpty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), CRAManifest{}))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))

	propsByName := map[string]string{}
	for _, p := range bom.Metadata.Properties {
		propsByName[p.Name] = p.Value
	}
	require.Equal(t, "13", propsByName["eu-cra:article"], "CRA article reference is unconditional")
	require.NotContains(t, propsByName, "eu-cra:manufacturer-country")
	require.NotContains(t, propsByName, "eu-cra:product-category")
	require.NotContains(t, propsByName, "eu-cra:support-lifecycle-end")
}

// ── components inheritance from regular CycloneDX ──────────────

func TestCRAJSONComponentsMatchRegularCycloneDX(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, result, sampleManifest()))
	var bom craBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Len(t, bom.Components, len(result.Dependencies))
	for _, c := range bom.Components {
		require.NotEmpty(t, c.Name)
		require.NotEmpty(t, c.BOMRef)
	}
}

func TestCRAJSONIsPrettyPrinted(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CRAJSON(&buf, sampleResult(), sampleManifest()))
	require.Contains(t, buf.String(), "\n  ")
}

// ── helpers ────────────────────────────────────────────────────

func TestOrValueReturnsFirstWhenNonEmpty(t *testing.T) {
	require.Equal(t, "real", orValue("real", "fallback"))
	require.Equal(t, "fallback", orValue("", "fallback"))
}

func TestBasenameOrEmpty(t *testing.T) {
	require.Equal(t, "project", basenameOrEmpty("/some/project"))
	require.Equal(t, "lib.go", basenameOrEmpty("a/b/c/lib.go"))
	require.Equal(t, "foo", basenameOrEmpty(`C:\Users\me\foo`))
	require.Equal(t, "noslash", basenameOrEmpty("noslash"))
	require.Equal(t, "", basenameOrEmpty(""))
}

func TestLicscanToolPopulated(t *testing.T) {
	tool := licscanTool()
	require.Equal(t, "licscan", tool.Name)
	require.Equal(t, "codelake Technologies LLC", tool.Vendor)
	require.NotEmpty(t, tool.Version)
}

// Verify the property keys follow the eu-cra: namespace convention so
// downstream tooling can filter them out predictably.
func TestCRAPropertyNamesAreNamespaced(t *testing.T) {
	props := craProperties(sampleManifest())
	for _, p := range props {
		require.True(t, strings.HasPrefix(p.Name, "eu-cra:"),
			"all CRA properties must use eu-cra: prefix, got %q", p.Name)
	}
}
