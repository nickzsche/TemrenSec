package scanner

import (
	"context"
	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FormParameterScanner tests form parameters for vulnerabilities
type FormParameterScanner struct{}

func NewFormParameterScanner() *FormParameterScanner {
	return &FormParameterScanner{}
}

func (s *FormParameterScanner) Name() string {
	return "Form Parameter Testing"
}

func (s *FormParameterScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err != nil {
		return findings, nil
	}

	body, _ := readBody(resp)
	resp.Body.Close()

	parser := httpengine.NewFormParser()
	forms, err := parser.ParseForms(body, target)
	if err != nil || len(forms) == 0 {
		return findings, nil
	}

	for _, form := range forms {
		for fieldName := range form.Fields {
			for _, payload := range payloads.XSS {
				formData := url.Values{}
				for k, v := range form.Fields {
					if k == fieldName {
						formData.Set(k, payload)
					} else {
						formData.Set(k, v)
					}
				}

				var resp *http.Response
				if form.Method == "POST" {
					resp, err = client.Post(ctx, form.Action, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
				} else {
					testURL := form.Action + "?" + formData.Encode()
					resp, err = client.Get(ctx, testURL)
				}

				if err != nil {
					continue
				}

				respBody, _ := readBody(resp)
				resp.Body.Close()

				if strings.Contains(string(respBody), payload) || strings.Contains(string(respBody), "<script>") {
					findings = append(findings, Finding{
						URL:         form.Action,
						Title:       "XSS in Form Parameter",
						Description: "Cross-Site Scripting in form field: " + fieldName,
						Severity:    SeverityHigh,
						Confidence:  ConfidenceHigh,
						Payload:     payload,
						Evidence:    "Payload reflected in form submission response",
						Scanner:     s.Name(),
						Timestamp:   time.Now(),
					})
					break
				}
			}

			for _, payload := range payloads.SQLInjection {
				formData := url.Values{}
				for k, v := range form.Fields {
					if k == fieldName {
						formData.Set(k, payload)
					} else {
						formData.Set(k, v)
					}
				}

				var resp *http.Response
				if form.Method == "POST" {
					resp, err = client.Post(ctx, form.Action, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
				} else {
					testURL := form.Action + "?" + formData.Encode()
					resp, err = client.Get(ctx, testURL)
				}

				if err != nil {
					continue
				}

				respBody, _ := readBody(resp)
				resp.Body.Close()

				sqlScanner := &SQLiScanner{}
				if sqlScanner.detectSQLError(string(respBody)) {
					findings = append(findings, Finding{
						URL:         form.Action,
						Title:       "SQL Injection in Form Parameter",
						Description: "SQL injection in form field: " + fieldName,
						Severity:    SeverityCritical,
						Confidence:  ConfidenceHigh,
						Payload:     payload,
						Evidence:    "SQL error detected in form submission response",
						Scanner:     s.Name(),
						Timestamp:   time.Now(),
					})
					break
				}
			}
		}
	}

	return findings, nil
}

