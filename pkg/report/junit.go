package report

import (
	"encoding/xml"
	"fmt"

	"github.com/temren/pkg/scanner"
)

// JUnit XML types for Jenkins/GitLab CI compatible output.

type junitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	TestSuites []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string           `xml:"name,attr"`
	Classname string           `xml:"classname,attr"`
	Time      string           `xml:"time,attr,omitempty"`
	Error     *junitError      `xml:"error,omitempty"`
	Failure   *junitFailure    `xml:"failure,omitempty"`
}

type junitError struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Content string `xml:",chardata"`
}

type junitFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Content string `xml:",chardata"`
}

// GenerateJUnit produces a JUnit XML string from findings.
// Critical/High findings produce <error> elements (CI fail).
// Medium/Low findings produce <failure> elements (CI warn).
// Info findings are plain testcases (no failure).
func GenerateJUnit(findings []scanner.Finding, targetURL string) (string, error) {
	if len(findings) == 0 {
		findings = []scanner.Finding{}
	}

	suite := junitTestSuite{
		Name: "Temren Security Scan",
	}

	for _, f := range findings {
		tc := junitTestCase{
			Name:      fmt.Sprintf("%s %s", f.Title, formatFindingURL(f)),
			Classname: string(f.Severity),
		}

		content := formatJUnitContent(f)

		switch f.Severity {
		case scanner.SeverityCritical, scanner.SeverityHigh:
			tc.Error = &junitError{
				Type:    f.Scanner,
				Message: fmt.Sprintf("Found %s in %s", f.Title, formatFindingURL(f)),
				Content: content,
			}
			suite.Errors++

		case scanner.SeverityMedium, scanner.SeverityLow:
			tc.Failure = &junitFailure{
				Type:    f.Scanner,
				Message: fmt.Sprintf("Found %s in %s", f.Title, formatFindingURL(f)),
				Content: content,
			}
			suite.Failures++

		default:
		}

		suite.TestCases = append(suite.TestCases, tc)
	}

	suite.Tests = len(suite.TestCases)

	suites := junitTestSuites{
		TestSuites: []junitTestSuite{suite},
	}

	output, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal junit xml: %w", err)
	}

	return xml.Header + string(output), nil
}

func (r *Report) GenerateJUnitReport() (string, error) {
	return GenerateJUnit(r.Findings, r.Target)
}

func (r *Report) SaveJUnit(filename string) error {
	content, err := r.GenerateJUnitReport()
	if err != nil {
		return err
	}
	return writeFile(filename, []byte(content))
}

func formatFindingURL(f scanner.Finding) string {
	if f.URL != "" {
		if f.Parameter != "" {
			return fmt.Sprintf("%s (%s)", f.URL, f.Parameter)
		}
		return f.URL
	}
	return ""
}

func formatJUnitContent(f scanner.Finding) string {
	var content string
	if f.Payload != "" {
		content += fmt.Sprintf("Payload: %s\n", f.Payload)
	}
	if f.Evidence != "" {
		content += fmt.Sprintf("Evidence: %s\n", f.Evidence)
	}
	if f.URL != "" {
		content += fmt.Sprintf("URL: %s\n", f.URL)
	}
	if f.Parameter != "" {
		content += fmt.Sprintf("Parameter: %s\n", f.Parameter)
	}
	if f.Description != "" {
		content += fmt.Sprintf("Description: %s\n", f.Description)
	}
	return content
}
