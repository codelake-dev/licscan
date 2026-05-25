package format

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/scanner/policy"
	"github.com/codelake-dev/licscan/internal/version"
)

// SARIF renders the result as a SARIF 2.1.0 log suitable for upload to
// GitHub Code Scanning via actions/upload-sarif.
//
// Only dependencies with a non-empty Verdict of "warn" or "deny" produce
// results — permissive dependencies are omitted to keep the output focused
// on actionable findings.
func SARIF(w io.Writer, result *scanner.Result) error {
	log := buildSARIF(result)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func buildSARIF(result *scanner.Result) sarifLog {
	rules := []sarifRule{}
	ruleIndex := map[string]int{}
	results := []sarifResult{}

	for _, dep := range result.Dependencies {
		if dep.Verdict != policy.VerdictWarn && dep.Verdict != policy.VerdictDeny {
			continue
		}

		ruleID := sarifRuleID(dep)
		idx, exists := ruleIndex[ruleID]
		if !exists {
			idx = len(rules)
			ruleIndex[ruleID] = idx
			rules = append(rules, sarifRuleForDep(dep, ruleID))
		}

		results = append(results, sarifResultForDep(dep, ruleID, idx))
	}

	return sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:            "licscan",
					InformationURI:  "https://licscan.dev",
					SemanticVersion: version.Version,
					Rules:           rules,
				},
			},
			Results: results,
		}},
	}
}

func sarifRuleID(dep scanner.Dependency) string {
	license := dep.PrimaryLicense()
	risk := dep.PrimaryRisk()
	return fmt.Sprintf("license/%s/%s", sarifSeverity(risk), license)
}

func sarifRuleForDep(dep scanner.Dependency, ruleID string) sarifRule {
	license := dep.PrimaryLicense()
	risk := dep.PrimaryRisk()
	level := sarifSeverity(risk)

	return sarifRule{
		ID:   ruleID,
		Name: fmt.Sprintf("%s license: %s", risk.String(), license),
		ShortDescription: sarifMessage{
			Text: fmt.Sprintf("Dependency uses %s license (%s)", license, risk.String()),
		},
		FullDescription: sarifMessage{
			Text: fmt.Sprintf("A dependency is licensed under %s, classified as %s risk. Review your project's license policy.", license, risk.String()),
		},
		DefaultConfiguration: sarifDefaultConfig{
			Level: level,
		},
		Properties: sarifRuleProperties{
			Tags: []string{"license", "compliance", "sbom", level},
		},
	}
}

func sarifResultForDep(dep scanner.Dependency, ruleID string, ruleIdx int) sarifResult {
	msg := fmt.Sprintf("%s@%s uses %s (%s)", dep.Name, dep.Version, dep.PrimaryLicense(), dep.PrimaryRisk().String())
	if dep.Reason != "" {
		msg += " — " + dep.Reason
	}

	return sarifResult{
		RuleID:    ruleID,
		RuleIndex: ruleIdx,
		Level:     sarifSeverity(dep.PrimaryRisk()),
		Message:   sarifMessage{Text: msg},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI:       dep.Manifest,
					URIBaseID: "%SRCROOT%",
				},
			},
		}},
		Properties: sarifResultProperties{
			Package:   dep.Name,
			Version:   dep.Version,
			License:   dep.PrimaryLicense(),
			Ecosystem: dep.Ecosystem,
			Verdict:   dep.Verdict,
		},
	}
}

func sarifSeverity(risk scanner.RiskLevel) string {
	switch risk {
	case scanner.RiskViral, scanner.RiskStrongCopyleft:
		return "error"
	case scanner.RiskWeakCopyleft:
		return "warning"
	default:
		return "note"
	}
}

// --- SARIF 2.1.0 struct types ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     sarifMessage        `json:"shortDescription"`
	FullDescription      sarifMessage        `json:"fullDescription"`
	DefaultConfiguration sarifDefaultConfig  `json:"defaultConfiguration"`
	Properties           sarifRuleProperties `json:"properties"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string                `json:"ruleId"`
	RuleIndex  int                   `json:"ruleIndex"`
	Level      string                `json:"level"`
	Message    sarifMessage          `json:"message"`
	Locations  []sarifLocation       `json:"locations"`
	Properties sarifResultProperties `json:"properties,omitempty"`
}

type sarifResultProperties struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	License   string `json:"license"`
	Ecosystem string `json:"ecosystem"`
	Verdict   string `json:"verdict"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}
