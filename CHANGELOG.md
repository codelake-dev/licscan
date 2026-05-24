# Changelog

All notable changes to `licscan` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 6 (SPDX 2.3 exporter)

- **SPDX 2.3 JSON SBOM** via `--format spdx` per https://spdx.github.io/spdx-spec/v2.3/.
- Includes `SPDXRef-DOCUMENT` + `creationInfo` (with `Tool: licscan-<version>`) + `packages[]` + `relationships[]` (`DESCRIBES`).
- `NOASSERTION` for unknown licenses + `downloadLocation`.
- PURL embedded as `externalRefs[].referenceLocator` (category `PACKAGE-MANAGER`, type `purl`).
- SPDXID sanitisation enforces the spec regex `^SPDXRef-[a-zA-Z0-9.\-]+$` so package names with `/`, `@`, etc. produce valid IDs.
- Verified end-to-end against a 337-dep Astro project — 7431-line valid SPDX 2.3 JSON.

### Added — Phase 5 (CycloneDX 1.5 exporter + PURL)

- **CycloneDX 1.5 JSON SBOM** via `--format cyclonedx` per https://cyclonedx.org/docs/1.5/json/. Accepted by Trivy, Grype, Snyk, Dependency-Track.
- Includes `bomFormat`, `specVersion`, `serialNumber` as `urn:uuid:<RFC4122-v4>` (crypto/rand, no external uuid dep), `metadata.tools[]` declaring licscan, `metadata.component` for the scan target, and `components[]` with `bom-ref`, `purl`, `licenses`, and `scope` (`required`/`optional` for direct/transitive).
- `NOASSERTION` license expression for unknown licenses (per CycloneDX convention).
- **PURL (Package URL) generator** per https://github.com/package-url/purl-spec — supports `pkg:golang`, `pkg:npm` (incl. scoped `@scope/pkg`), `pkg:composer`, `pkg:pypi`, `pkg:gem`, `pkg:cargo`, `pkg:maven`. Re-used by both CycloneDX and SPDX exporters.

### Added — Phase 4 (HTML formatter)

- **Dark-theme HTML report**: single self-contained HTML5 file, no external CSS/JS, can be archived as CI artifact and opened anywhere.
- **Summary cards**: per-risk-level count with colour-coded badges (green/yellow/red/purple/grey).
- **Sortable dependency table**: rows sorted by descending risk so the dangerous stuff appears first.
- **XSS-safe rendering**: all user-supplied strings (package names, license IDs, paths) flow through `html/template` for automatic escaping. Malicious package names like `<script>alert(1)</script>` are properly escaped.
- **Detector-error surfacing**: per-detector errors rendered as a dedicated alert section.
- **`licscan scan . --format html > report.html`** now produces a real report (was JSON placeholder).

### Added — Phase 3 (npm detector)

- **npm detector**: parses `package.json` (direct deps across `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`) and `package-lock.json`. Handles all three lockfile generations: v1 (nested tree), v2 (compat + flat), v3 (flat only).
- **License-field extractor**: handles all four shapes used in the wild — string SPDX, `{type: "..."}`  object (legacy), `[{type: "..."}]` array (legacy), and SPDX expressions like `(MIT OR Apache-2.0)`.
- **`SEE LICENSE IN ...` indirection**: detected and forwarded to the LICENSE-file scanner fallback instead of being mis-classified as Unknown.
- **NodeModulesResolver**: inspects `node_modules/<pkg>/package.json` first, falls back to `LICENSE` / `LICENCE` / `COPYING` file text identification.
- **Scoped package handling**: `@babel/core`, `@img/sharp-libvips-*` etc. parse correctly.
- **Risk-map extension**: BlueOak-1.0.0, Artistic-2.0, UPL-1.0, OFL-1.1 added as Permissive.

Verified end-to-end against a 337-dependency Astro project — every license classified, 0 Unknowns.

### Added — Phase 2 (go.mod detector)

- **Scanner engine**: `internal/scanner` with pluggable `Detector` interface and orchestrator.
- **Risk classification**: 5-level model (Unknown / Permissive / Weak Copyleft / Strong Copyleft / Viral) covering 40+ SPDX identifiers.
- **SPDX text identifier**: heuristic matcher for MIT / Apache-2.0 / BSD-2-Clause / BSD-3-Clause / ISC / 0BSD / GPL-2 / GPL-3 / LGPL-2.1 / LGPL-3 / AGPL-3 / MPL-2 / EPL / CDDL / EUPL / SSPL / BUSL / Unlicense / CC0 / Zlib.
- **go.mod detector**: parses `go.mod` (direct + indirect), resolves licenses from the local Go module cache, marks unresolved as `Unknown` with a remediation note.
- **Table formatter**: aligned terminal output sorted by descending risk, with risk emojis.
- **JSON formatter**: stable schema for CI/CD consumption.
- **CI mode**: `--ci` exits non-zero when any Strong-Copyleft / Viral dependency is found.

### Added — Phase 1 (foundation)

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
