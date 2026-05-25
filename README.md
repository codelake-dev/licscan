<div align="center">

```
  _      _       _____                 
 | |    (_)     / ____|                
 | |     _  ___| (___   ___ __ _ _ __  
 | |    | |/ __|\___ \ / __/ _` | '_ \ 
 | |____| | (__ ____) | (_| (_| | | | |
 |______|_|\___|_____/ \___\__,_|_| |_|
```

**Open-source license & compliance scanner for modern codebases.**

[![CI](https://github.com/codelake-dev/licscan/actions/workflows/ci.yml/badge.svg)](https://github.com/codelake-dev/licscan/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/codelake-dev/licscan)](https://github.com/codelake-dev/licscan/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/codelake-dev/licscan.svg)](https://pkg.go.dev/github.com/codelake-dev/licscan)
[![Go Report Card](https://goreportcard.com/badge/github.com/codelake-dev/licscan)](https://goreportcard.com/report/github.com/codelake-dev/licscan)

</div>

---

> 👀 **See it in action:** [`example-outputs/`](example-outputs/) contains every format licscan can produce — table, JSON, HTML report, CycloneDX + SPDX SBOMs, Markdown for PR comments, and a full EU CRA evidence pair (PDF + JSON). Real output from a real scan, no installation required.

## What is licscan?

`licscan` scans a project for the licenses of its dependencies, classifies them by risk, checks whether the combination can be shipped, and exports a standards-compliant SBOM (CycloneDX 1.5 / SPDX 2.3).

It is built for engineering teams who want license compliance to be a deterministic, scriptable part of CI — not a quarterly fire-drill.

### Supported package managers

| Ecosystem | Manifest |
|---|---|
| PHP | `composer.json`, `composer.lock` |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml` |
| Go | `go.mod`, `go.sum` |
| Ruby | `Gemfile`, `Gemfile.lock` |
| Rust | `Cargo.toml`, `Cargo.lock` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts` |

### Risk classification

| Marker | Class | Examples |
|---|---|---|
| ✅ | Permissive | MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC |
| ⚠️ | Weak Copyleft | LGPL-2.1, LGPL-3.0, MPL-2.0 |
| 🔴 | Strong Copyleft | GPL-2.0, GPL-3.0 |
| ❌ | Viral / Problematic | AGPL-3.0, SSPL, BSL-1.1, Commons-Clause |

---

## Installation

### One-liner (macOS / Linux)

```bash
curl -fsSL https://install.codelake.dev/licscan/install.sh | sh
```

Installs the latest stable release into `/usr/local/bin/licscan`. Override with:
- `LICSCAN_VERSION=v0.11.0` — pin a specific version
- `LICSCAN_INSTALL_DIR=$HOME/.local/bin` — install elsewhere (no sudo)

### Homebrew (macOS, Linux)

```bash
brew install codelake-dev/tap/licscan
```

### Go install

```bash
go install github.com/codelake-dev/licscan/cmd/licscan@latest
```

### Manual download

Pre-built binaries for Linux, macOS and Windows (amd64 + arm64) are attached to each [GitHub Release](https://github.com/codelake-dev/licscan/releases).

```bash
# macOS (Apple Silicon)
curl -L -o licscan https://github.com/codelake-dev/licscan/releases/latest/download/licscan-darwin-arm64
chmod +x licscan && sudo mv licscan /usr/local/bin/

# Linux (x86_64)
curl -L -o licscan https://github.com/codelake-dev/licscan/releases/latest/download/licscan-linux-amd64
chmod +x licscan && sudo mv licscan /usr/local/bin/
```

Windows users: download `licscan-windows-amd64.exe` from the release page and add it to your PATH.

---

## Quickstart

```bash
# Scan the current directory
licscan scan .

# Scan a specific project
licscan scan ~/code/my-project

# Choose an output format
licscan scan . --format json
licscan scan . --format html > report.html
licscan scan . --format cyclonedx > sbom.json

# Run in CI — exit 1 on policy violation
licscan scan . --ci

# Generate an EU CRA-compliant SBOM
licscan scan . --cra
```

---

## Commands

### `licscan scan [path]`

Scan a directory tree for dependency licenses.

| Flag | Default | Description |
|---|---|---|
| `--format`, `-f` | `table` | Output format: `table`, `json`, `html`, `cyclonedx`, `spdx`, `markdown` |
| `--ci` | `false` | CI mode — non-zero exit code on policy violation |
| `--cra` | `false` | Emit EU CRA-compliant SBOM (PDF + JSON) |

### `licscan about`

Print the banner, version, and attribution.

### `licscan --version`

Print the version, commit hash and build date.

### `licscan --help`

Print the help text for any command. Works on subcommands too:

```bash
licscan scan --help
licscan about --help
```

---

## Policy engine

Drop a `.licscan.yml` into your project root to define what `--ci` should reject or warn about:

```yaml
deny:
  - AGPL-3.0
  - SSPL-1.0
  - GPL-2.0

warn:
  - GPL-3.0
  - LGPL-3.0

allow_exceptions:
  - package: some-gpl-lib
    reason: "only used in tests, never bundled"
```

When `licscan scan . --ci` runs in a CI pipeline:

- a finding for any `deny` license → **exit 1** (with the violating packages printed to stderr)
- a finding for any `warn` license → reported with a `⚠ warn` verdict, exit 0
- a finding for a package listed under `allow_exceptions` → marked `○ exempt`, exit 0

If no `.licscan.yml` is present, a built-in default policy applies: denies GPL / AGPL / SSPL / BSL / Commons-Clause / Elastic-2.0; warns on LGPL / MPL / EPL / CDDL / EUPL; allows Permissive (MIT / Apache / BSD / ISC / …).

---

## CI integration

### GitHub Actions

The recommended way is the official **[`codelake-dev/licscan-action`](https://github.com/codelake-dev/licscan-action)** — installs the binary, scans the repo, posts the markdown report as a PR comment, and uploads the report as a workflow artefact in one step:

```yaml
on: [pull_request]
jobs:
  licenses:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: codelake-dev/licscan-action@v1
```

See the [action README](https://github.com/codelake-dev/licscan-action#readme) for all inputs (`version` pin, `path`, `cra`, `fail-on-violation`, `pr-comment`, ...) and recipes (release-time CRA archive, custom logic via outputs).

If you'd rather wire the CLI manually:

```yaml
- name: License compliance
  run: |
    curl -fsSL https://install.codelake.dev/licscan/install.sh | sh
    licscan scan . --ci --format markdown
```

### GitLab CI

```yaml
license_scan:
  image: alpine:latest
  script:
    - apk add --no-cache curl tar
    - curl -L https://github.com/codelake-dev/licscan/releases/latest/download/licscan_Linux_x86_64.tar.gz | tar xz
    - ./licscan scan . --ci
  artifacts:
    when: always
    reports:
      cyclonedx: sbom.json
    paths:
      - sbom.json
```

---

## Markdown report (PR comments / READMEs)

```bash
licscan scan . --format markdown
```

Produces a GitHub-flavored Markdown report — paste it into a PR comment, an issue body, a README, or a Slack message. Includes:

- Summary table per risk level (with emoji markers)
- Full dependency table sorted by descending risk
- Auto-collapses (`<details>`) when the dep count exceeds 30, so big lockfiles stay readable in PR threads
- Adds a `Verdict` column and a `## Policy violations` section when a `.licscan.yml` is in effect

Typical CI snippet (post the report as a PR comment):

```bash
licscan scan . --format markdown > /tmp/report.md
gh pr comment "$PR_NUMBER" --body-file /tmp/report.md
```

## SBOM export

`licscan` produces SBOMs in two industry-standard formats:

```bash
licscan scan . --format cyclonedx > sbom.cdx.json   # CycloneDX 1.5
licscan scan . --format spdx      > sbom.spdx.json  # SPDX 2.3
```

Both formats include canonical PURLs (`pkg:golang/...`, `pkg:npm/...`, etc.) and are accepted by the major vulnerability scanners (Trivy, Grype, Snyk) and dependency-tracking platforms (Dependency-Track, FOSSA, DependencyHub). The CycloneDX BOM serial number is a stable RFC 4122 v4 UUID; the SPDX document namespace is a unique URI per scan.

---

## EU CRA Compliance Mode

The EU Cyber Resilience Act (Regulation (EU) 2024/2847) requires manufacturers of "products with digital elements" to maintain a machine-readable SBOM with specific metadata (Article 13, Annex I §1(2)(s)). `--cra` emits both a CycloneDX 1.5 JSON SBOM **and** a regulator-ready PDF in one pass:

```bash
licscan scan . --cra
# → ./licscan-cra-evidence/cra-sbom.cdx.json
# → ./licscan-cra-evidence/cra-evidence.pdf
```

Custom output directory:

```bash
licscan scan . --cra --output ./compliance/
```

### Manufacturer metadata

Set the required CRA Article 13(2) producer identity in `.licscan.yml`:

```yaml
manufacturer:
  name: Acme GmbH
  email: security@acme.example
  url: https://acme.example
  country: DE

product:
  name: my-app
  version: 1.2.3
  category: important
  support_lifecycle_end: "2031-05-24"
```

Without a manufacturer block, the evidence is still generated, but the PDF cover carries a warning that submission to a regulator requires the four required fields.

### What gets generated

**`cra-sbom.cdx.json`** — CycloneDX 1.5 SBOM (machine-readable) with CRA-specific extensions: `metadata.manufacturer`, `metadata.supplier` (licscan itself), `metadata.lifecycles.phase=operations`, and `metadata.properties[]` carrying the regulation, article, annex, manufacturer country, product category, and support-lifecycle-end as `eu-cra:*` namespaced properties.

**`cra-evidence.pdf`** — regulator-friendly summary (human-readable):
- Cover page with manufacturer + product + scan metadata + about-this-document statement
- License risk summary table (counts per risk level, colour-coded)
- Full dependency inventory sorted by descending risk

> **Not legal advice.** This document *supports* CRA evidence collection — it does not *constitute* a declaration of conformity. The manufacturer remains responsible for verifying the inventory is complete and that listed components have been subjected to the vulnerability-handling processes required by the Regulation. Work with your legal / compliance team to confirm scope before submission.

---

## Compile from source

Requires Go 1.22 or later.

```bash
git clone https://github.com/codelake-dev/licscan
cd licscan

# Run all tests
make test

# Build a local binary
make build

# Install into $GOPATH/bin
make install

# Cross-compile for all release targets (requires goreleaser)
make release-dry-run
```

Without `make`:

```bash
go test ./...
go build -o ./bin/licscan ./cmd/licscan
go install ./cmd/licscan
```

### Project layout

```
licscan/
├── cmd/licscan/        # CLI entry point (main package)
├── internal/
│   ├── cli/            # Cobra command tree
│   ├── version/        # Build-time metadata (ldflags-injected)
│   └── banner/         # ASCII logo + attribution
├── .github/workflows/  # CI + release pipelines
├── .goreleaser.yml     # Cross-platform release config
└── .golangci.yml       # Lint config
```

---

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow, commit conventions, and how to run the full test suite locally.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for third-party attributions.

---

<div align="center">

**LicScan** · by [codelake Technologies LLC](https://codelake.dev). An Akyros Labs brand.

</div>
