# Changelog

All notable changes to `licscan` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Foundation skeleton: Cobra-based CLI with `scan`, `about`, `--version`, `--help`.
- ASCII banner with attribution to codelake Technologies LLC.
- `--format` flag accepting `table`, `json`, `html`, `cyclonedx`, `spdx`, `markdown`.
- `--ci` flag for CI-mode (non-zero exit on policy violation, behaviour lands with scanner implementation).
- `--cra` flag for EU CRA-compliant SBOM emission (behaviour lands with scanner implementation).
- GitHub Actions CI matrix: linux/macos/windows × amd64/arm64.
- Goreleaser configuration for tag-triggered cross-platform binary releases.
- `golangci-lint` configuration with strict defaults.
- Test coverage: 100% on `internal/version` and `internal/banner`, ≥ 79% on `internal/cli`.

### Notes

The actual scanning logic (package-manager detection, SPDX resolution, policy engine, SBOM export, EU CRA mode) lands in subsequent releases. This release establishes the public CLI contract, attribution, build pipeline and test foundation.
