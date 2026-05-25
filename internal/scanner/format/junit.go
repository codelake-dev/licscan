package format

import (
	"encoding/xml"
	"fmt"
	"io"
	"time"

	"github.com/codelake-dev/licscan/internal/scanner"
	"github.com/codelake-dev/licscan/internal/scanner/policy"
	"github.com/codelake-dev/licscan/internal/version"
)

// JUnit renders the result as JUnit XML compatible with Jenkins, GitLab CI,
// Azure DevOps and other CI systems that ingest xUnit-style reports.
// Each dependency is a testcase; warn/deny/incompatible verdicts are failures.
func JUnit(w io.Writer, result *scanner.Result) error {
	suite := buildJUnitSuite(result)
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(suite)
}

func buildJUnitSuite(result *scanner.Result) junitTestSuites {
	cases := make([]junitTestCase, 0, len(result.Dependencies))
	var failures, errors int

	for _, dep := range result.Dependencies {
		tc := junitTestCase{
			Name:      fmt.Sprintf("%s@%s", dep.Name, dep.Version),
			ClassName: fmt.Sprintf("licscan.%s", dep.Ecosystem),
			Time:      "0",
		}

		switch dep.Verdict {
		case policy.VerdictDeny, policy.VerdictIncompat:
			tc.Failure = &junitFailure{
				Message: fmt.Sprintf("%s: %s", dep.PrimaryLicense(), dep.Reason),
				Type:    dep.Verdict,
				Content: fmt.Sprintf("Package %s@%s uses %s (%s). %s",
					dep.Name, dep.Version, dep.PrimaryLicense(), dep.PrimaryRisk(), dep.Reason),
			}
			failures++
		case policy.VerdictWarn:
			tc.Failure = &junitFailure{
				Message: fmt.Sprintf("%s: %s", dep.PrimaryLicense(), dep.Reason),
				Type:    "warning",
				Content: fmt.Sprintf("Package %s@%s uses %s (%s). %s",
					dep.Name, dep.Version, dep.PrimaryLicense(), dep.PrimaryRisk(), dep.Reason),
			}
			failures++
		}

		cases = append(cases, tc)
	}

	return junitTestSuites{
		Suites: []junitTestSuite{{
			Name:      "licscan",
			Tests:     len(result.Dependencies),
			Failures:  failures,
			Errors:    errors,
			Time:      "0",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Properties: []junitProperty{
				{Name: "licscan.version", Value: version.Short()},
				{Name: "scan.path", Value: result.ScanPath},
			},
			TestCases: cases,
		}},
	}
}

type junitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Errors     int             `xml:"errors,attr"`
	Time       string          `xml:"time,attr"`
	Timestamp  string          `xml:"timestamp,attr"`
	Properties []junitProperty `xml:"properties>property"`
	TestCases  []junitTestCase `xml:"testcase"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}
