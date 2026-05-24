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

### Homebrew (macOS, Linux)

```bash
brew install codelake-dev/tap/licscan
```

### Scoop (Windows)

```powershell
scoop bucket add codelake-dev https://github.com/codelake-dev/scoop-bucket
scoop install licscan
```

### Go install

```bash
go install github.com/codelake-dev/licscan/cmd/licscan@latest
```

### Manual download

Pre-built binaries for Linux, macOS and Windows (amd64 + arm64) are attached to each [GitHub Release](https://github.com/codelake-dev/licscan/releases).

```bash
# Linux / macOS
curl -L https://github.com/codelake-dev/licscan/releases/latest/download/licscan_$(uname -s)_$(uname -m).tar.gz | tar xz
sudo mv licscan /usr/local/bin/
```

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

```yaml
- name: License compliance
  run: |
    curl -L https://github.com/codelake-dev/licscan/releases/latest/download/licscan_Linux_x86_64.tar.gz | tar xz
    ./licscan scan . --ci --format json > license-report.json
- uses: actions/upload-artifact@v4
  with:
    name: license-report
    path: license-report.json
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

## SBOM export

`licscan` produces SBOMs in two industry-standard formats:

```bash
licscan scan . --format cyclonedx > sbom.cdx.json   # CycloneDX 1.5
licscan scan . --format spdx      > sbom.spdx.json  # SPDX 2.3
```

Both formats include canonical PURLs (`pkg:golang/...`, `pkg:npm/...`, etc.) and are accepted by the major vulnerability scanners (Trivy, Grype, Snyk) and dependency-tracking platforms (Dependency-Track, FOSSA, DependencyHub). The CycloneDX BOM serial number is a stable RFC 4122 v4 UUID; the SPDX document namespace is a unique URI per scan.

---

## EU CRA Compliance Mode

The EU Cyber Resilience Act (CRA) requires manufacturers of "products with digital elements" to maintain a machine-readable SBOM that includes specific metadata fields. `--cra` emits both a CycloneDX SBOM and a regulator-ready PDF in one pass:

```bash
licscan scan . --cra --output ./cra-evidence/
```

This is not legal advice — work with your DPO / compliance team to confirm scope. `licscan` *supports* CRA evidence collection; it does not *certify* you as CRA-compliant.

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
