package lsp

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/scanner/policy"
)

func buildDiagnostics(root string, result *scanner.Result) map[string][]diagnostic {
	byURI := make(map[string][]diagnostic)

	manifestContents := make(map[string][]string)

	for _, dep := range result.Dependencies {
		manifest := dep.Manifest
		if manifest == "" {
			continue
		}

		absManifest := manifest
		if !filepath.IsAbs(manifest) {
			absManifest = filepath.Join(root, manifest)
		}
		uri := pathToURI(absManifest)

		lines, ok := manifestContents[absManifest]
		if !ok {
			data, err := os.ReadFile(absManifest)
			if err != nil {
				continue
			}
			lines = strings.Split(string(data), "\n")
			manifestContents[absManifest] = lines
		}

		line, col, endCol := findDepLine(lines, dep)

		sev := verdictToSeverity(dep.Verdict, dep.PrimaryRisk())
		if sev == 0 {
			continue
		}

		license := dep.PrimaryLicense()
		risk := dep.PrimaryRisk().String()
		msg := formatDiagMessage(dep, license, risk)

		d := diagnostic{
			Range: diagRange{
				Start: position{Line: line, Character: col},
				End:   position{Line: line, Character: endCol},
			},
			Severity: sev,
			Source:   "licscan",
			Code:     license,
			Message:  msg,
			Data: &diagnosticData{
				License:   license,
				Risk:      risk,
				Verdict:   dep.Verdict,
				Ecosystem: dep.Ecosystem,
			},
		}

		byURI[uri] = append(byURI[uri], d)
	}

	return byURI
}

func buildInlayHints(path, content string, result *scanner.Result) []inlayHint {
	lines := strings.Split(content, "\n")
	base := filepath.Base(path)

	var hints []inlayHint

	for _, dep := range result.Dependencies {
		if filepath.Base(dep.Manifest) != base {
			continue
		}

		line, _, endCol := findDepLine(lines, dep)
		if line < 0 {
			continue
		}

		license := dep.PrimaryLicense()
		risk := dep.PrimaryRisk()

		label := license
		tooltip := risk.String()
		if dep.Verdict != "" && dep.Verdict != policy.VerdictAllow {
			tooltip += " · " + dep.Verdict
		}

		hints = append(hints, inlayHint{
			Position:    position{Line: line, Character: endCol},
			Label:       label,
			Kind:        1,
			Tooltip:     tooltip,
			PaddingLeft: true,
		})
	}

	return hints
}

func findDepLine(lines []string, dep scanner.Dependency) (line, col, endCol int) {
	name := dep.Name
	ver := dep.Version

	shortName := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		shortName = name[idx+1:]
	}

	for i, l := range lines {
		lower := strings.ToLower(l)
		if strings.Contains(l, name) || strings.Contains(lower, strings.ToLower(shortName)) {
			if ver != "" && !strings.Contains(l, ver) && !containsVersionish(l, ver) {
				continue
			}
			col := strings.Index(l, name)
			if col < 0 {
				col = indexCaseInsensitive(l, shortName)
			}
			if col < 0 {
				col = 0
			}
			endCol := len(l)
			return i, col, endCol
		}
	}

	for i, l := range lines {
		if strings.Contains(l, name) || strings.Contains(strings.ToLower(l), strings.ToLower(shortName)) {
			col := strings.Index(l, name)
			if col < 0 {
				col = indexCaseInsensitive(l, shortName)
			}
			if col < 0 {
				col = 0
			}
			return i, col, len(l)
		}
	}

	return 0, 0, 0
}

func containsVersionish(line, ver string) bool {
	clean := strings.TrimPrefix(ver, "v")
	return strings.Contains(line, clean)
}

func indexCaseInsensitive(s, substr string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(substr))
}

func verdictToSeverity(verdict string, risk scanner.RiskLevel) int {
	switch verdict {
	case policy.VerdictDeny, policy.VerdictIncompat:
		return severityError
	case policy.VerdictWarn:
		return severityWarning
	case policy.VerdictAllow, policy.VerdictExempt:
		return severityHint
	default:
		switch risk {
		case scanner.RiskViral, scanner.RiskStrongCopyleft:
			return severityError
		case scanner.RiskWeakCopyleft:
			return severityWarning
		case scanner.RiskUnknown:
			return severityInformation
		default:
			return severityHint
		}
	}
}

func formatDiagMessage(dep scanner.Dependency, license, risk string) string {
	base := dep.Name + "@" + dep.Version + " · " + license + " (" + risk + ")"
	if dep.Reason != "" {
		base += " — " + dep.Reason
	}
	return base
}
