package detectors

// Ecosystem identifiers used in Dependency.Ecosystem.
const (
	ecosystemGoMod    = "gomod"
	ecosystemNpm      = "npm"
	ecosystemComposer = "composer"
	ecosystemCargo    = "cargo"
	ecosystemGem      = "gem"
	ecosystemPip      = "pip"
	ecosystemMaven    = "maven"
)

// Manifest file basenames used in Dependency.Manifest.
const (
	manifestGoMod        = "go.mod"
	manifestComposerJSON = "composer.json"
	manifestComposerLock = "composer.lock"
	manifestPackageJSON  = "package.json"
	manifestPackageLock  = "package-lock.json"
	manifestCargoTOML    = "Cargo.toml"
	manifestCargoLock    = "Cargo.lock"
	manifestGemfileLock  = "Gemfile.lock"
	manifestPomXML       = "pom.xml"
	manifestPoetryLock   = "poetry.lock"
	manifestPipfileLock  = "Pipfile.lock"
	manifestRequirements = "requirements.txt"
	manifestPyproject    = "pyproject.toml"
)

// Frequently-resolved SPDX identifiers — centralised so the goconst
// linter is happy and updates touch one place. Detector-specific
// patterns (e.g. mavenLicensePatterns) may still use these as values.
const (
	spdxMIT        = "MIT"
	spdxApache20   = "Apache-2.0"
	spdxBSD2Clause = "BSD-2-Clause"
	spdxBSD3Clause = "BSD-3-Clause"
	spdxISC        = "ISC"
	spdxEPL10      = "EPL-1.0"
	spdxMPL20      = "MPL-2.0"
	spdxLGPL21     = "LGPL-2.1"
	spdxGPL20      = "GPL-2.0"
	spdxGPL30      = "GPL-3.0"
	spdxAGPL30     = "AGPL-3.0"
	spdxCC010      = "CC0-1.0"
)
