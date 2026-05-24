package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Real license-text fragments sufficient for matching. Kept short so the
// test file stays readable; the matcher works on text, not file size.

const mitFragment = `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.`

const apache2Fragment = `                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/`

const bsd3Fragment = `BSD 3-Clause License

Copyright (c) 2024, Example.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice.
2. Redistributions in binary form must reproduce the above copyright notice.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.`

const bsd2Fragment = `BSD 2-Clause License

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice.
2. Redistributions in binary form must reproduce the above copyright notice.`

const iscFragment = `ISC License

Copyright (c) 2024 Example

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.`

const gpl3Fragment = `                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc.`

const lgpl3Fragment = `                   GNU LESSER GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007`

const agpl3Fragment = `                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007`

const mpl2Fragment = `Mozilla Public License Version 2.0
==================================`

const unlicenseFragment = `This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software.`

const sspl1Fragment = `Server Side Public License
VERSION 1, October 16, 2018`

func TestIdentifyLicenseDetectsMIT(t *testing.T) {
	require.Equal(t, "MIT", IdentifyLicense(mitFragment))
}

func TestIdentifyLicenseDetectsApache2(t *testing.T) {
	require.Equal(t, "Apache-2.0", IdentifyLicense(apache2Fragment))
}

func TestIdentifyLicenseDetectsBSD3(t *testing.T) {
	require.Equal(t, "BSD-3-Clause", IdentifyLicense(bsd3Fragment))
}

func TestIdentifyLicenseDetectsBSD2NotBSD3(t *testing.T) {
	// BSD-2 must not be mis-detected as BSD-3 just because of the shared opening clause.
	require.Equal(t, "BSD-2-Clause", IdentifyLicense(bsd2Fragment))
}

func TestIdentifyLicenseDetectsISC(t *testing.T) {
	require.Equal(t, "ISC", IdentifyLicense(iscFragment))
}

func TestIdentifyLicenseDetectsGPL3(t *testing.T) {
	require.Equal(t, "GPL-3.0", IdentifyLicense(gpl3Fragment))
}

func TestIdentifyLicenseDetectsLGPL3NotGPL3(t *testing.T) {
	// Critical: LGPL must not be confused with GPL.
	require.Equal(t, "LGPL-3.0", IdentifyLicense(lgpl3Fragment))
}

func TestIdentifyLicenseDetectsAGPL3NotGPL3(t *testing.T) {
	// Critical: AGPL must not be confused with GPL.
	require.Equal(t, "AGPL-3.0", IdentifyLicense(agpl3Fragment))
}

func TestIdentifyLicenseDetectsMPL2(t *testing.T) {
	require.Equal(t, "MPL-2.0", IdentifyLicense(mpl2Fragment))
}

func TestIdentifyLicenseDetectsUnlicense(t *testing.T) {
	require.Equal(t, "Unlicense", IdentifyLicense(unlicenseFragment))
}

func TestIdentifyLicenseDetectsSSPL(t *testing.T) {
	require.Equal(t, "SSPL-1.0", IdentifyLicense(sspl1Fragment))
}

func TestIdentifyLicenseReturnsEmptyForUnknown(t *testing.T) {
	custom := `My Company Internal License v1.0

This software is the proprietary work of MyCompany. All rights reserved.
Use without explicit written permission is prohibited.`
	require.Equal(t, "", IdentifyLicense(custom))
}

func TestIdentifyLicenseReturnsEmptyForEmptyInput(t *testing.T) {
	require.Equal(t, "", IdentifyLicense(""))
}

func TestIdentifyLicenseHandlesWhitespaceVariations(t *testing.T) {
	// Tab + multiple spaces should match the same as single space.
	weirdMIT := "MIT\t\tLicense\n\n\nPermission\tis  hereby\tgranted, free of charge\nthe software is provided \"as is\""
	require.Equal(t, "MIT", IdentifyLicense(weirdMIT))
}

func TestIdentifyLicenseCaseInsensitive(t *testing.T) {
	upper := `THE APACHE LICENSE
VERSION 2.0`
	require.Equal(t, "Apache-2.0", IdentifyLicense(upper))
}

func TestNormaliseCollapsesWhitespace(t *testing.T) {
	require.Equal(t, "foo bar baz", normaliseLicenseText("foo   bar\n\nbaz"))
	require.Equal(t, "foo bar", normaliseLicenseText("FOO\tBAR"))
}
