package scanner

import (
	"fmt"
	"path/filepath"
)

// Scanner orchestrates a set of Detectors against a project root.
//
// Detectors are independent: each one is tried in turn, and a single
// detector's error does not abort the scan — its error is appended to
// Result.Errors and the remaining detectors still run.
type Scanner struct {
	detectors []Detector
}

// New builds a Scanner with the given detectors registered.
// Order matters only for the Detectors-Run list in the Result.
func New(detectors ...Detector) *Scanner {
	return &Scanner{detectors: detectors}
}

// Register adds another detector to the scanner. Safe to call after New().
func (s *Scanner) Register(d Detector) {
	s.detectors = append(s.detectors, d)
}

// Scan runs every registered detector against rootPath and aggregates
// their findings into a single Result. The path is resolved to an
// absolute path before any detector runs so error messages are stable.
func (s *Scanner) Scan(rootPath string) (*Result, error) {
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("resolve scan path %q: %w", rootPath, err)
	}

	result := NewResult(absRoot)

	for _, d := range s.detectors {
		found, deps, err := d.Detect(absRoot)
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: %s", d.Name(), err.Error()))
			continue
		}
		if !found {
			continue
		}

		result.Detectors = append(result.Detectors, d.Name())
		for _, dep := range deps {
			result.Add(dep)
		}
	}

	return result, nil
}
