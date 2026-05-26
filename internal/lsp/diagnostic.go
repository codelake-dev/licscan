package lsp

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/scanner/policy"
)

var companionManifests = map[string]string{
	"composer.lock":     "composer.json",
	"package-lock.json": "package.json",
	"Cargo.lock":        "Cargo.toml",
	"Gemfile.lock":      "Gemfile",
	"poetry.lock":       "pyproject.toml",
	"go.sum":            "go.mod",
}

func buildDiagnostics(root string, result *scanner.Result) map[string][]diagnostic {
	byURI := make(map[string][]diagnostic)
	manifestContents := make(map[string][]string)

	readLines := func(absPath string) []string {
		if lines, ok := manifestContents[absPath]; ok {
			return lines
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			return nil
		}
		lines := strings.Split(string(data), "\n")
		manifestContents[absPath] = lines
		return lines
	}

	for _, dep := range result.Dependencies {
		manifest := dep.Manifest
		if manifest == "" {
			continue
		}

		absManifest := manifest
		if !filepath.IsAbs(manifest) {
			absManifest = filepath.Join(root, manifest)
		}

		targets := []string{absManifest}
		if companion, ok := companionManifests[filepath.Base(manifest)]; ok {
			targets = append(targets, filepath.Join(filepath.Dir(absManifest), companion))
		}

		sev := verdictToSeverity(dep.Verdict, dep.PrimaryRisk())
		license := dep.PrimaryLicense()
		risk := dep.PrimaryRisk().String()
		msg := formatDiagMessage(dep, license, risk)

		for _, target := range targets {
			lines := readLines(target)
			if lines == nil {
				continue
			}

			line, col, endCol := findDepLine(lines, dep)
			if line == 0 && col == 0 && endCol == 0 {
				continue
			}

			uri := pathToURI(target)
			byURI[uri] = append(byURI[uri], diagnostic{
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
			})
		}
	}

	return byURI
}

func buildInlayHints(path, content string, result *scanner.Result) []inlayHint {
	lines := strings.Split(content, "\n")
	base := filepath.Base(path)

	if !isRelatedManifest(base) {
		return nil
	}

	hints := make([]inlayHint, 0, len(result.Dependencies))

	for _, dep := range result.Dependencies {
		line, _, endCol := findDepLine(lines, dep)
		if line == 0 && endCol == 0 {
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

var relatedManifests = map[string]bool{
	"go.mod": true, "go.sum": true,
	"package.json": true, "package-lock.json": true,
	"composer.json": true, "composer.lock": true,
	"Cargo.toml": true, "Cargo.lock": true,
	"Gemfile": true, "Gemfile.lock": true,
	"pyproject.toml": true, "poetry.lock": true, "Pipfile.lock": true, "requirements.txt": true,
	"pom.xml": true,
}

func isRelatedManifest(base string) bool {
	return relatedManifests[base]
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
		return severityInformation
	default:
		switch risk {
		case scanner.RiskViral, scanner.RiskStrongCopyleft:
			return severityError
		case scanner.RiskWeakCopyleft:
			return severityWarning
		default:
			return severityInformation
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
