# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in licscan, **please do not open a public issue**.

Instead, report it privately via one of these channels:

1. **GitHub private vulnerability reporting** — preferred:
   [github.com/codelake-dev/licscan/security/advisories/new](https://github.com/codelake-dev/licscan/security/advisories/new)
2. **Email** — `security@codelake.dev`

Please include:

- A clear description of the issue
- Steps to reproduce (a minimal failing project / config helps)
- The licscan version (`licscan --version`)
- Your OS + architecture
- Any suggested mitigation

## Response timeline

| Stage | Target |
|---|---|
| Acknowledge receipt | 72 hours |
| Initial assessment | 7 days |
| Fix or risk-accept decision | 30 days |
| Public disclosure | coordinated with reporter |

We will credit you in the release notes and the published advisory unless you ask us not to.

## Supported versions

We currently support security fixes for the latest minor release line.

| Version | Supported |
|---|---|
| 0.11.x | ✅ |
| < 0.11 | ❌ |

Once 1.0.0 ships, the previous minor will also be supported for 90 days.

## Scope

In scope:

- The licscan CLI binary and any code in this repository.
- The official Homebrew formula (`codelake-dev/homebrew-tap`).
- The official GitHub Action (`codelake-dev/licscan-action`).
- The `install.sh` script published at `https://install.codelake.dev/licscan/install.sh`.

Out of scope:

- Issues in third-party dependencies — please report those upstream and CC us if licscan is meaningfully affected.
- Reports that rely on running licscan against untrusted manifests with `--cra` and observing that the resulting SBOM cites those untrusted strings (we trust the manifest; the user pointed us at it).
- Findings that require local administrator privileges already.
