# Contributing to licscan

Thanks for considering a contribution! `licscan` is an open-source project under Apache License 2.0 and welcomes issues, pull requests, and discussion.

## Getting started

Requires Go 1.22+.

```bash
git clone https://github.com/codelake-ai/licscan
cd licscan
make test    # run the full test suite
make lint    # run golangci-lint
make build   # produce ./bin/licscan
```

## Submitting a pull request

1. **Fork** the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feat/short-description
   ```
2. **Write tests first**. Every new code path should have at least one test.
3. **Keep commits small and focused**. The commit message body explains the *why*.
4. **Run the full suite** before pushing:
   ```bash
   make test lint
   ```
5. **Open the PR** against `main` with a clear description of the change and any user-visible impact.

## Coding conventions

- Standard Go style — `gofmt` is enforced by CI.
- `golangci-lint` config in `.golangci.yml` is the source of truth.
- Public functions get short doc comments. Private functions only if non-obvious.
- No third-party dependencies without prior discussion in an issue.

## Test conventions

- Table-driven tests for anything with multiple input shapes.
- Use `github.com/stretchr/testify/require` for fast-fail assertions.
- Coverage gate: `internal/` packages should stay ≥ 80%.

## Reporting bugs

Open an issue with:
- `licscan --version` output
- OS + arch
- A minimal reproduction (ideally a public repo or `.licscan.yml` snippet)
- Expected vs actual behaviour

## Reporting security vulnerabilities

**Do not open a public issue for security reports.** Email security@codelake.dev with details and a suggested disclosure timeline. We aim to respond within 72 hours.

## Code of conduct

We follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Be excellent to each other.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0, the same license as the project.
