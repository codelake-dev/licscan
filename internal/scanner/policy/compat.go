package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codelake-dev/licscan/internal/scanner"
)

const (
	VerdictIncompat = "incompatible"

	cGPL2       = "gpl-2.0"
	cGPL2Only   = "gpl-2.0-only"
	cGPL2Later  = "gpl-2.0-or-later"
	cGPL3       = "gpl-3.0"
	cGPL3Only   = "gpl-3.0-only"
	cGPL3Later  = "gpl-3.0-or-later"
	cAGPL3      = "agpl-3.0"
	cAGPL3Only  = "agpl-3.0-only"
	cAGPL3Later = "agpl-3.0-or-later"
	cSSPL       = "sspl-1.0"
	cBUSL       = "busl-1.1"
	cBSL        = "bsl-1.1"
	cElastic    = "elastic-2.0"
	cElasticAlt = "elastic-license-2.0"
	cCommons    = "commons-clause"
)

// incompatViralSet contains licenses that are incompatible with almost
// every permissive/copyleft project license.
var incompatViralSet = map[string]bool{
	cAGPL3: true, cAGPL3Only: true, cAGPL3Later: true,
	cSSPL: true, cBUSL: true, cBSL: true,
}

// compatMatrix maps a project license (normalised) to the set of dependency
// licenses that are *incompatible* with it. Built at init from merge helpers.
var compatMatrix map[string]map[string]bool

func init() {
	gpl2All := map[string]bool{cGPL2: true, cGPL2Only: true, cGPL2Later: true}
	gpl3All := map[string]bool{cGPL3: true, cGPL3Only: true, cGPL3Later: true}
	proprietarySet := map[string]bool{cElastic: true, cElasticAlt: true, cCommons: true}

	permissiveIncompat := mergeSets(gpl2All, gpl3All, incompatViralSet)

	compatMatrix = map[string]map[string]bool{
		"mit":          mergeSets(permissiveIncompat, proprietarySet),
		"apache-2.0":   mergeSets(map[string]bool{cGPL2: true, cGPL2Only: true}, incompatViralSet, proprietarySet),
		"bsd-2-clause": permissiveIncompat,
		"bsd-3-clause": permissiveIncompat,
		"isc":          permissiveIncompat,
		cGPL2:          mergeSets(map[string]bool{cGPL3: true, cGPL3Only: true, "apache-2.0": true}, incompatViralSet),
		cGPL3:          mergeSets(map[string]bool{cGPL2: true, cGPL2Only: true}, incompatViralSet),
		"lgpl-2.1":     copySet(incompatViralSet),
		"lgpl-3.0":     mergeSets(map[string]bool{cGPL2: true, cGPL2Only: true}, incompatViralSet),
		"mpl-2.0":      copySet(incompatViralSet),
	}
}

func mergeSets(sets ...map[string]bool) map[string]bool {
	out := make(map[string]bool)
	for _, s := range sets {
		for k, v := range s {
			out[k] = v
		}
	}
	return out
}

func copySet(s map[string]bool) map[string]bool {
	return mergeSets(s)
}

// normalised aliases so users can write "MIT" or "Apache 2.0" in project_license.
var projectLicenseAliases = map[string]string{
	"apache 2.0":   "apache-2.0",
	"bsd 2-clause": "bsd-2-clause",
	"bsd 3-clause": "bsd-3-clause",
	"gpl-2.0-only": "gpl-2.0", "gpl-2.0-or-later": "gpl-2.0",
	"gpl-3.0-only": "gpl-3.0", "gpl-3.0-or-later": "gpl-3.0",
	"lgpl-2.1-only": "lgpl-2.1", "lgpl-2.1-or-later": "lgpl-2.1",
	"lgpl-3.0-only": "lgpl-3.0", "lgpl-3.0-or-later": "lgpl-3.0",
}

// DetectProjectLicense tries to find the project's own license.
// Priority: .licscan.yml project_license > LICENSE file in scan root.
func DetectProjectLicense(scanRoot string, pol *Policy) string {
	if pol.ProjectLicense != "" {
		return pol.ProjectLicense
	}
	return detectLicenseFile(scanRoot)
}

func detectLicenseFile(scanRoot string) string {
	candidates := []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "LICENCE.txt"}
	for _, name := range candidates {
		path := filepath.Join(scanRoot, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))
		return matchLicenseContent(content)
	}
	return ""
}

func matchLicenseContent(content string) string {
	patterns := []struct {
		needle string
		spdx   string
	}{
		{"apache license, version 2.0", "Apache-2.0"},
		{"apache license\n                           version 2.0", "Apache-2.0"},
		{"mit license", "MIT"},
		{"permission is hereby granted, free of charge", "MIT"},
		{"redistribution and use in source and binary forms", "BSD-3-Clause"},
		{"gnu general public license, version 3", "GPL-3.0"},
		{"gnu general public license, version 2", "GPL-2.0"},
		{"gnu lesser general public license", "LGPL-3.0"},
		{"gnu affero general public license", spdxAGPL3},
		{"mozilla public license, version 2.0", "MPL-2.0"},
		{"isc license", "ISC"},
		{"the unlicense", "Unlicense"},
	}
	for _, p := range patterns {
		if strings.Contains(content, p.needle) {
			return p.spdx
		}
	}
	return ""
}

// CheckCompatibility walks every dependency and checks if its license is
// compatible with the project's own license. Incompatible deps get their
// Verdict upgraded to VerdictIncompat (which is treated as deny-level)
// unless they are already exempt.
func CheckCompatibility(result *scanner.Result, projectLicense string) {
	if projectLicense == "" || result == nil {
		return
	}

	key := normaliseLicenseKey(projectLicense)
	if alias, ok := projectLicenseAliases[key]; ok {
		key = alias
	}

	incompat, ok := compatMatrix[key]
	if !ok {
		return
	}

	for i := range result.Dependencies {
		dep := &result.Dependencies[i]
		if dep.Verdict == VerdictExempt {
			continue
		}
		for _, lic := range dep.Licenses {
			depKey := normaliseLicenseKey(lic.SPDX)
			if incompat[depKey] {
				dep.Verdict = VerdictIncompat
				dep.Reason = fmt.Sprintf("license %s is incompatible with project license %s", lic.SPDX, projectLicense)
				break
			}
		}
	}
}
