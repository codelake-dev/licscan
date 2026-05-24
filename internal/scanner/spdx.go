package scanner

import (
	"regexp"
	"strings"
)

// IdentifyLicense inspects raw license-file text and returns the most
// likely SPDX identifier. Returns "" if no confident match is found —
// callers should treat that as "Unknown" rather than guessing.
//
// The matcher is heuristic, not exhaustive: it relies on distinctive
// phrases that appear in only one license family. This covers >95% of
// real-world OSS LICENSE files. Obscure / custom licenses fall through.
func IdentifyLicense(text string) string {
	normalised := normaliseLicenseText(text)

	for _, m := range matchers {
		if m.matches(normalised) {
			return m.spdx
		}
	}
	return ""
}

// normaliseLicenseText collapses all whitespace runs into a single space
// and lower-cases the string. Makes matching robust against formatting
// variations between projects.
func normaliseLicenseText(text string) string {
	text = strings.ToLower(text)
	return whitespaceRun.ReplaceAllString(text, " ")
}

var whitespaceRun = regexp.MustCompile(`\s+`)

// licenseMatcher describes how to recognise one license family.
// All `must` substrings must be present; any `mustNot` substring disqualifies.
type licenseMatcher struct {
	spdx    string
	must    []string
	mustNot []string
}

func (m licenseMatcher) matches(text string) bool {
	for _, s := range m.must {
		if !strings.Contains(text, s) {
			return false
		}
	}
	for _, s := range m.mustNot {
		if strings.Contains(text, s) {
			return false
		}
	}
	return true
}

// matchers is evaluated in order — more specific patterns must come first.
// (E.g. AGPL must precede LGPL must precede GPL, because the latter is a
// substring of the former.)
var matchers = []licenseMatcher{
	// Public-domain dedication — very distinctive opening phrase.
	{
		spdx: "Unlicense",
		must: []string{"this is free and unencumbered software released into the public domain"},
	},
	{
		spdx: "CC0-1.0",
		must: []string{"creative commons cc0", "no copyright"},
	},

	// 0BSD has identical permission grant to ISC, distinguished by the explicit "or without fee" phrasing.
	{
		spdx: "0BSD",
		must: []string{
			"permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted",
		},
		mustNot: []string{"isc"},
	},
	{
		spdx: "ISC",
		must: []string{
			"permission to use, copy, modify, and/or distribute this software for any purpose",
		},
	},

	// AGPL must come before LGPL/GPL because "GNU Affero General Public License"
	// also contains "GNU ... General Public License".
	{
		spdx: "AGPL-3.0",
		must: []string{"gnu affero general public license", "version 3"},
	},
	{
		spdx: "LGPL-3.0",
		must: []string{"gnu lesser general public license", "version 3"},
	},
	{
		spdx: "LGPL-2.1",
		must: []string{"gnu lesser general public license", "version 2.1"},
	},
	{
		spdx: "GPL-3.0",
		must:    []string{"gnu general public license", "version 3"},
		mustNot: []string{"lesser", "affero"},
	},
	{
		spdx: "GPL-2.0",
		must:    []string{"gnu general public license", "version 2"},
		mustNot: []string{"lesser", "affero"},
	},

	// Mozilla Public License.
	{
		spdx: "MPL-2.0",
		must: []string{"mozilla public license", "version 2.0"},
	},
	{
		spdx: "MPL-1.1",
		must: []string{"mozilla public license", "version 1.1"},
	},

	// Eclipse + CDDL.
	{
		spdx: "EPL-2.0",
		must: []string{"eclipse public license", "version 2.0"},
	},
	{
		spdx: "EPL-1.0",
		must: []string{"eclipse public license", "version 1.0"},
	},
	{
		spdx: "CDDL-1.1",
		must: []string{"common development and distribution license", "1.1"},
	},
	{
		spdx: "CDDL-1.0",
		must: []string{"common development and distribution license", "1.0"},
	},

	// European Union Public License.
	{
		spdx: "EUPL-1.2",
		must: []string{"european union public licence", "version 1.2"},
	},

	// Network-server-side-only commercial restrictions.
	{
		spdx: "SSPL-1.0",
		must: []string{"server side public license"},
	},
	{
		spdx: "BUSL-1.1",
		must: []string{"business source license"},
	},

	// MIT — distinctive permission grant phrase that no other major license uses.
	{
		spdx: "MIT",
		must: []string{
			"permission is hereby granted, free of charge",
			"the software is provided \"as is\"",
		},
	},

	// Apache-2.0 — "Apache License" + "Version 2.0".
	{
		spdx: "Apache-2.0",
		must: []string{"apache license", "version 2.0"},
	},

	// BSD-3-Clause has the "Neither the name of" clause; BSD-2-Clause does not.
	{
		spdx: "BSD-3-Clause",
		must: []string{
			"redistribution and use in source and binary forms",
			"neither the name of",
		},
	},
	{
		spdx: "BSD-2-Clause",
		must: []string{"redistribution and use in source and binary forms"},
		mustNot: []string{"neither the name of"},
	},

	// Zlib / libpng style.
	{
		spdx: "Zlib",
		must: []string{"this software is provided 'as-is'", "without any express or implied warranty"},
	},
}
