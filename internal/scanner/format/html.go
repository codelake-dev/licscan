package format

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/codelake-dev/licscan/internal/scanner"
)

// HTML renders the result as a single self-contained dark-theme HTML page.
// No external CSS or JS — the file can be archived as a CI artifact and
// opened in a browser anywhere.
//
// All user-supplied strings (dependency names, license IDs, paths) flow
// through html/template, which auto-escapes them. Malicious package names
// cannot inject script tags.
func HTML(w io.Writer, result *scanner.Result) error {
	data := htmlData{
		Result:       result,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Dependencies: sortByRiskDescending(result.Dependencies),
		RiskBuckets:  buildRiskBuckets(result.Summary),
		TotalCount:   len(result.Dependencies),
	}

	t, err := template.New("report").Funcs(template.FuncMap{
		"directLabel": func(b bool) string {
			if b {
				return "direct"
			}
			return "transitive"
		},
		"riskClass": func(d scanner.Dependency) string {
			return riskClassFor(d.PrimaryRisk())
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}
	return t.Execute(w, data)
}

type htmlData struct {
	Result       *scanner.Result
	GeneratedAt  string
	Dependencies []scanner.Dependency
	RiskBuckets  []riskBucket
	TotalCount   int
}

type riskBucket struct {
	Level scanner.RiskLevel
	Label string
	Emoji string
	Count int
	Class string
}

func sortByRiskDescending(deps []scanner.Dependency) []scanner.Dependency {
	out := make([]scanner.Dependency, len(deps))
	copy(out, deps)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PrimaryRisk() != out[j].PrimaryRisk() {
			return out[i].PrimaryRisk() > out[j].PrimaryRisk()
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func buildRiskBuckets(summary map[string]int) []riskBucket {
	return []riskBucket{
		{scanner.RiskViral, scanner.RiskViral.String(), scanner.RiskViral.Emoji(), summary[scanner.RiskViral.String()], "viral"},
		{scanner.RiskStrongCopyleft, scanner.RiskStrongCopyleft.String(), scanner.RiskStrongCopyleft.Emoji(), summary[scanner.RiskStrongCopyleft.String()], "strong"},
		{scanner.RiskWeakCopyleft, scanner.RiskWeakCopyleft.String(), scanner.RiskWeakCopyleft.Emoji(), summary[scanner.RiskWeakCopyleft.String()], "weak"},
		{scanner.RiskPermissive, scanner.RiskPermissive.String(), scanner.RiskPermissive.Emoji(), summary[scanner.RiskPermissive.String()], "permissive"},
		{scanner.RiskUnknown, scanner.RiskUnknown.String(), scanner.RiskUnknown.Emoji(), summary[scanner.RiskUnknown.String()], "unknown"},
	}
}

// riskClassFor maps a RiskLevel to its CSS class for the per-row badge.
func riskClassFor(r scanner.RiskLevel) string {
	switch r {
	case scanner.RiskPermissive:
		return "permissive"
	case scanner.RiskWeakCopyleft:
		return "weak"
	case scanner.RiskStrongCopyleft:
		return "strong"
	case scanner.RiskViral:
		return "viral"
	default:
		return "unknown"
	}
}

// riskClassForName looks up the CSS class via the dependency's PrimaryRisk.
// Exposed as a template function so the template stays declarative.
func init() {
	htmlTemplate = headTemplate + bodyTemplate
}

var htmlTemplate string

const headTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LicScan Report — {{.Result.ScanPath}}</title>
<style>
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --surface-2: #21262d;
  --border: #30363d;
  --text: #e6edf3;
  --muted: #8b949e;
  --accent: #58a6ff;
  --permissive: #3fb950;
  --weak: #d29922;
  --strong: #f85149;
  --viral: #a371f7;
  --unknown: #6e7681;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.5;
}
.container { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }
header { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }
header .top { display: flex; align-items: center; justify-content: space-between; gap: 24px; }
header .top-text { flex: 1 1 auto; min-width: 0; }
header .top-logo { flex: 0 0 auto; }
header .top-logo img { height: 50px; width: auto; display: block; }
header h1 { margin: 0 0 4px; font-size: 28px; font-weight: 600; }
header .tagline { color: var(--muted); font-size: 14px; }
header .meta { margin-top: 16px; color: var(--muted); font-size: 13px; }
header .meta strong { color: var(--text); font-weight: 500; }

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 32px; }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
}
.card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 8px; }
.card .count { font-size: 28px; font-weight: 600; }
.card.viral .count { color: var(--viral); }
.card.strong .count { color: var(--strong); }
.card.weak .count { color: var(--weak); }
.card.permissive .count { color: var(--permissive); }
.card.unknown .count { color: var(--unknown); }

table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
thead { background: var(--surface-2); }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); }
th { font-weight: 500; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
tbody tr:hover { background: var(--surface-2); }
tbody tr:last-child td { border-bottom: 0; }
td.pkg { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
td.version { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--muted); }
td.license { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
td.scope { color: var(--muted); font-size: 12px; }

.badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: 500; }
.badge.permissive { background: rgba(63, 185, 80, 0.15); color: var(--permissive); }
.badge.weak { background: rgba(210, 153, 34, 0.15); color: var(--weak); }
.badge.strong { background: rgba(248, 81, 73, 0.15); color: var(--strong); }
.badge.viral { background: rgba(163, 113, 247, 0.15); color: var(--viral); }
.badge.unknown { background: rgba(110, 118, 129, 0.15); color: var(--unknown); }

.empty { padding: 48px; text-align: center; color: var(--muted); background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }

footer { margin-top: 48px; padding-top: 24px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; text-align: center; }
footer a { color: var(--accent); text-decoration: none; }
footer a:hover { text-decoration: underline; }

.errors { margin-bottom: 32px; padding: 16px 20px; background: rgba(248, 81, 73, 0.08); border: 1px solid rgba(248, 81, 73, 0.3); border-radius: 8px; color: var(--text); }
.errors h3 { margin: 0 0 8px; color: var(--strong); font-size: 14px; }
.errors ul { margin: 0; padding-left: 20px; }
.errors li { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
</style>
</head>
`

const bodyTemplate = `<body>
<div class="container">
  <header>
    <div class="top">
      <div class="top-text">
        <h1>LicScan Report</h1>
        <div class="tagline">Open-source license &amp; compliance scan</div>
      </div>
      <div class="top-logo">
        <img src="https://cdn.codelake.dev/logo/codelake_logo_w.png" alt="codelake">
      </div>
    </div>
    <div class="meta">
      <div><strong>Scan path:</strong> {{.Result.ScanPath}}</div>
      <div><strong>Detectors:</strong>
        {{range $i, $d := .Result.Detectors}}{{if $i}}, {{end}}{{$d}}{{else}}none{{end}}
      </div>
      <div><strong>Total dependencies:</strong> {{.TotalCount}}</div>
      <div><strong>Generated:</strong> {{.GeneratedAt}}</div>
    </div>
  </header>

  <section class="cards">
    {{range .RiskBuckets}}
    <div class="card {{.Class}}">
      <div class="label">{{.Emoji}} {{.Label}}</div>
      <div class="count">{{.Count}}</div>
    </div>
    {{end}}
  </section>

  {{if .Result.Errors}}
  <div class="errors">
    <h3>Detector errors</h3>
    <ul>
      {{range .Result.Errors}}<li>{{.}}</li>{{end}}
    </ul>
  </div>
  {{end}}

  {{if .Dependencies}}
  <table>
    <thead>
      <tr>
        <th>Risk</th>
        <th>Package</th>
        <th>Version</th>
        <th>License</th>
        <th>Scope</th>
        <th>Ecosystem</th>
      </tr>
    </thead>
    <tbody>
      {{range .Dependencies}}
      <tr>
        <td><span class="badge {{riskClass .}}">{{.PrimaryRisk}}</span></td>
        <td class="pkg">{{.Name}}</td>
        <td class="version">{{.Version}}</td>
        <td class="license">{{.PrimaryLicense}}</td>
        <td class="scope">{{directLabel .Direct}}</td>
        <td class="scope">{{.Ecosystem}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No dependencies found.</div>
  {{end}}

  <footer>
    LicScan · by codelake Technologies LLC · An Akyros Labs brand ·
    <a href="https://github.com/codelake-dev/licscan">github.com/codelake-dev/licscan</a>
  </footer>
</div>
</body>
</html>
`
