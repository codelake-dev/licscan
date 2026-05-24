package scanner

// Detector inspects a project root for a specific package-manager manifest
// (go.mod, package.json, composer.json, ...) and emits the dependencies
// it finds along with their licenses.
//
// Implementations live in internal/scanner/detectors and are registered
// with a Scanner via Register().
type Detector interface {
	// Name returns the short identifier used in Result.Detectors and in
	// error messages. Examples: "gomod", "npm", "composer".
	Name() string

	// Detect walks rootPath looking for this detector's manifest. It
	// returns whether a manifest was found, the discovered dependencies,
	// and any non-fatal warnings the caller should surface.
	//
	// A "manifest not found" result is not an error — Detect returns
	// found=false, no deps, no error. Errors are reserved for genuine
	// problems (unreadable file, malformed manifest, etc.).
	Detect(rootPath string) (found bool, deps []Dependency, err error)
}
