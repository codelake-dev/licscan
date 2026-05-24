package format

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestCycloneDXProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, sampleResult()))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
}

func TestCycloneDXHasRequiredTopLevelFields(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, sampleResult()))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))

	require.Equal(t, "CycloneDX", bom.BOMFormat)
	require.Equal(t, "1.5", bom.SpecVersion)
	require.Equal(t, 1, bom.Version)
	require.NotEmpty(t, bom.SerialNumber)
}

func TestCycloneDXSerialNumberIsValidURNUUID(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, sampleResult()))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))

	uuidPattern := regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	require.True(t, uuidPattern.MatchString(bom.SerialNumber),
		"serialNumber must be urn:uuid:<RFC4122-v4-UUID>, got %s", bom.SerialNumber)
}

func TestCycloneDXMetadataIncludesLicscanTool(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, sampleResult()))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))

	require.Len(t, bom.Metadata.Tools, 1)
	require.Equal(t, "licscan", bom.Metadata.Tools[0].Name)
	require.Equal(t, "codelake Technologies LLC", bom.Metadata.Tools[0].Vendor)
	require.NotEmpty(t, bom.Metadata.Tools[0].Version)
}

func TestCycloneDXMetadataTopLevelComponent(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, sampleResult()))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))

	require.Equal(t, "application", bom.Metadata.Component.Type)
	require.NotEmpty(t, bom.Metadata.Component.Name, "top-level component must have a name")
	require.NotEmpty(t, bom.Metadata.Component.BOMRef)
}

func TestCycloneDXComponentsCountMatchesDependencies(t *testing.T) {
	result := sampleResult()

	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, result))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Len(t, bom.Components, len(result.Dependencies))
}

func TestCycloneDXComponentEachHasNameAndBOMRef(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, sampleResult()))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))

	for _, c := range bom.Components {
		require.NotEmpty(t, c.Name, "every component must have a name")
		require.NotEmpty(t, c.BOMRef, "every component must have a bom-ref")
		require.Equal(t, "library", c.Type, "deps are libraries")
	}
}

func TestCycloneDXEmitsValidPURLForGoMod(t *testing.T) {
	r := scanner.NewResult("/project")
	r.Add(scanner.Dependency{
		Name: "github.com/spf13/cobra", Version: "v1.10.2", Ecosystem: "gomod", Direct: true,
		Licenses: []scanner.License{scanner.NewLicense("Apache-2.0", "")},
	})

	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, r))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Equal(t, "pkg:golang/github.com/spf13/cobra@v1.10.2", bom.Components[0].PURL)
}

func TestCycloneDXEmitsLicenseAsID(t *testing.T) {
	r := scanner.NewResult("/project")
	r.Add(scanner.Dependency{
		Name: "lib", Version: "1.0.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")},
	})

	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, r))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Len(t, bom.Components[0].Licenses, 1)
	require.NotNil(t, bom.Components[0].Licenses[0].License)
	require.Equal(t, "MIT", bom.Components[0].Licenses[0].License.ID)
}

func TestCycloneDXEmitsNOASSERTIONForUnknownLicense(t *testing.T) {
	r := scanner.NewResult("/project")
	r.Add(scanner.Dependency{
		Name: "mystery-lib", Version: "1.0.0", Ecosystem: "npm",
		Licenses: []scanner.License{scanner.NewLicense("Unknown", "")},
	})

	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, r))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Equal(t, "NOASSERTION", bom.Components[0].Licenses[0].Expression)
}

func TestCycloneDXScopeRequiredForDirectOptionalForTransitive(t *testing.T) {
	r := scanner.NewResult("/project")
	r.Add(scanner.Dependency{Name: "direct-lib", Version: "1.0", Ecosystem: "npm", Direct: true,
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")}})
	r.Add(scanner.Dependency{Name: "transitive-lib", Version: "1.0", Ecosystem: "npm", Direct: false,
		Licenses: []scanner.License{scanner.NewLicense("MIT", "")}})

	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, r))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))

	scopes := map[string]string{}
	for _, c := range bom.Components {
		scopes[c.Name] = c.Scope
	}
	require.Equal(t, "required", scopes["direct-lib"])
	require.Equal(t, "optional", scopes["transitive-lib"])
}

func TestCycloneDXHandlesEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, scanner.NewResult("/empty")))

	var bom cycloneDXBOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bom))
	require.Equal(t, "1.5", bom.SpecVersion)
	require.Empty(t, bom.Components)
}

func TestCycloneDXIsPrettyPrinted(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, CycloneDX(&buf, sampleResult()))
	require.Contains(t, buf.String(), "\n  ", "must be pretty-printed (indented)")
}

func TestNewUUIDProducesValidV4Format(t *testing.T) {
	uuid := newUUID()
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	require.True(t, pattern.MatchString(uuid), "got %s", uuid)
}

func TestNewUUIDProducesDifferentValuesEachCall(t *testing.T) {
	a := newUUID()
	b := newUUID()
	require.NotEqual(t, a, b, "UUIDs must be unique across calls")
}
