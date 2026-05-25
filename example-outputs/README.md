# Sample outputs

Every output format `licscan` can produce — captured against a real Go project (licscan scanning itself) so you can see exactly what to expect before installing anything.

All files in this directory were generated with:

```bash
licscan scan ./project --format <format>
licscan scan ./project --cra --output ./example-outputs/
```

…against a fixture project whose `.licscan.yml` declares:

```yaml
manufacturer:
  name: codelake Technologies LLC
  email: hello@codelake.dev
  url: https://codelake.dev
  country: US

product:
  name: licscan
  version: 0.11.0
  category: important
  support_lifecycle_end: "2031-05-25"
```

> **Privacy note:** the `source` paths in `scan.json` have been scrubbed of the local username (`/Users/sascha` → `/Users/example`). Everything else is untouched — these are exactly the bytes licscan emits.

---

## Files in this directory

| File | Format | Use case |
|---|---|---|
| [`scan.table.txt`](scan.table.txt) | Plain text (terminal) | What you see on stdout from `licscan scan .` — aligned columns, risk emojis, summary footer |
| [`scan.json`](scan.json) | Pretty JSON | Machine-readable; pipe into `jq`, dashboards, custom scripts |
| [`scan.html`](scan.html) | Self-contained HTML | Dark-theme report with codelake header logo. Open in any browser; archive as a CI artifact. Single file, no external CSS/JS |
| [`scan.md`](scan.md) | GitHub-flavored Markdown | Paste into a PR comment / README / Slack — uses `<details>` auto-collapse when >30 deps |
| [`scan.cyclonedx.json`](scan.cyclonedx.json) | CycloneDX 1.5 SBOM | Industry-standard SBOM, accepted by Trivy / Grype / Snyk / Dependency-Track |
| [`scan.spdx.json`](scan.spdx.json) | SPDX 2.3 SBOM | The other industry-standard SBOM; expected by some regulators / compliance tools |
| [`scan.sarif.json`](scan.sarif.json) | SARIF 2.1.0 | Upload to GitHub Code Scanning via `actions/upload-sarif`. Only warn/deny findings appear as results; permissive deps are omitted. This example shows a synthetic project with one MPL-2.0 warning and one AGPL-3.0 denial |
| [`scan.junit.xml`](scan.junit.xml) | JUnit XML | Compatible with Jenkins, GitLab CI, Azure DevOps and any CI that ingests xUnit reports. Each dependency is a testcase; warn/deny/incompatible verdicts are test failures |
| [`cra-evidence.pdf`](cra-evidence.pdf) | PDF | EU CRA Article 13 evidence — cover page with manufacturer + product + scan metadata + summary table + dependency inventory. Generated together with the JSON below via `--cra` |
| [`cra-sbom.cdx.json`](cra-sbom.cdx.json) | CycloneDX 1.5 + CRA extensions | The machine-readable counterpart to the PDF — CycloneDX SBOM with `metadata.manufacturer`, `metadata.lifecycles[].phase=operations`, and `eu-cra:*` namespaced properties |

---

## What is *not* shown here

Each file is one scan against one project that happens to ship 10 permissive-licensed Go dependencies (cobra · testify · pflag · x/mod · fpdf · yaml.v3 · BurntSushi/toml · plus their indirect deps). That means:

- **No policy violations to display.** All ten dependencies are MIT / Apache-2.0 / BSD / ISC and the default policy allows them. In a real-world scan with GPL / AGPL / LGPL dependencies, the Markdown and HTML outputs would gain a `Policy violations` section and the table would show a `Verdict` column populated with ✗ deny / ⚠ warn / ✓ allow / ○ exempt.
- **No `Unknown` licenses.** All deps had a locally-resolvable LICENSE file under `$GOPATH/pkg/mod/...`. In a fresh checkout without `go mod download`, you'd see `Unknown` with explanatory notes.

To see those branches, pass `--cra` over a project with a `.licscan.yml` that deny-lists something one of your dependencies actually uses.

---

## Regenerating these files

```bash
# Pin to a stable licscan version
LICSCAN_VERSION=v0.11.0 curl -fsSL https://install.codelake.dev/licscan/install.sh | sh

# Generate every format
for f in table json html cyclonedx spdx markdown sarif junit; do
  licscan scan ./your-project --format "$f" > "example-outputs/scan.${f}"
done

# CRA evidence (writes both files)
licscan scan ./your-project --cra --output example-outputs/
```

---

← [Back to licscan README](../README.md)
