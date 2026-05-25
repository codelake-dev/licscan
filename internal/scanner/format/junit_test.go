package format

import (
	"bytes"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codelake-dev/licscan/internal/scanner"
)

func TestJUnitProducesValidXML(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JUnit(&buf, sampleResult()))

	var parsed junitTestSuites
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &parsed))
}

func TestJUnitSuiteHasCorrectCounts(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JUnit(&buf, sampleResultWithVerdicts()))

	var parsed junitTestSuites
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &parsed))

	require.Len(t, parsed.Suites, 1)
	suite := parsed.Suites[0]
	assert.Equal(t, 3, suite.Tests)
	assert.Equal(t, 2, suite.Failures, "warn + deny should be failures")
	assert.Equal(t, "licscan", suite.Name)
}

func TestJUnitTestCaseNames(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JUnit(&buf, sampleResultWithVerdicts()))

	var parsed junitTestSuites
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &parsed))

	names := make([]string, len(parsed.Suites[0].TestCases))
	for i, tc := range parsed.Suites[0].TestCases {
		names[i] = tc.Name
	}
	assert.Contains(t, names, "lib-mit@v1.0.0")
	assert.Contains(t, names, "lib-mpl@v2.1.0")
	assert.Contains(t, names, "lib-agpl@v2.0.0")
}

func TestJUnitAllowedDepHasNoFailure(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JUnit(&buf, sampleResultWithVerdicts()))

	var parsed junitTestSuites
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &parsed))

	for _, tc := range parsed.Suites[0].TestCases {
		if tc.Name == "lib-mit@v1.0.0" {
			assert.Nil(t, tc.Failure, "allowed dep should have no failure")
		}
	}
}

func TestJUnitDenyIsFailure(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JUnit(&buf, sampleResultWithVerdicts()))

	var parsed junitTestSuites
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &parsed))

	for _, tc := range parsed.Suites[0].TestCases {
		if tc.Name == "lib-agpl@v2.0.0" {
			require.NotNil(t, tc.Failure)
			assert.Equal(t, "deny", tc.Failure.Type)
			assert.Contains(t, tc.Failure.Content, "AGPL-3.0")
		}
	}
}

func TestJUnitWarnIsFailure(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JUnit(&buf, sampleResultWithVerdicts()))

	var parsed junitTestSuites
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &parsed))

	for _, tc := range parsed.Suites[0].TestCases {
		if tc.Name == "lib-mpl@v2.1.0" {
			require.NotNil(t, tc.Failure)
			assert.Equal(t, "warning", tc.Failure.Type)
		}
	}
}

func TestJUnitEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JUnit(&buf, scanner.NewResult("/empty")))

	var parsed junitTestSuites
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &parsed))

	assert.Equal(t, 0, parsed.Suites[0].Tests)
	assert.Equal(t, 0, parsed.Suites[0].Failures)
}

func TestJUnitContainsProperties(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JUnit(&buf, sampleResult()))

	var parsed junitTestSuites
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &parsed))

	props := parsed.Suites[0].Properties
	require.Len(t, props, 2)
	assert.Equal(t, "licscan.version", props[0].Name)
	assert.Equal(t, "scan.path", props[1].Name)
}
