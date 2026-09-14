package scanner

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
)

// CommandInjectionScanner detects OS command injection using two techniques:
// output-based (command output echoed into the response) and time-based blind
// (an injected sleep/ping measurably delays the response).
type CommandInjectionScanner struct {
	SleepSeconds int
}

func NewCommandInjectionScanner() *CommandInjectionScanner {
	return &CommandInjectionScanner{SleepSeconds: 5}
}

func (s *CommandInjectionScanner) Name() string {
	return "Command Injection"
}

func (s *CommandInjectionScanner) sleepSeconds() int {
	if s.SleepSeconds <= 0 {
		return 5
	}
	return s.SleepSeconds
}

// Scan tests for command injection.
func (s *CommandInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	for param := range query {
		orig := query.Get(param)

		if f, ok := s.testOutputBased(ctx, client, u, query, param); ok {
			findings = append(findings, f)
			query.Set(param, orig)
			continue
		}

		if f, ok := s.testTimeBlind(ctx, client, u, query, param, orig); ok {
			findings = append(findings, f)
		}

		query.Set(param, orig)
	}

	return findings, nil
}

// testOutputBased is the original technique: look for command output in the body.
func (s *CommandInjectionScanner) testOutputBased(ctx context.Context, client *httpengine.Client, u *url.URL, query url.Values, param string) (Finding, bool) {
	for _, payload := range payloads.CommandInjection {
		testURL := buildURL(u, query, param, payload)
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}
		body, _ := readBody(resp)
		resp.Body.Close()

		if s.detectCommandOutput(string(body)) {
			return Finding{
				URL:           testURL,
				Title:         "OS Command Injection (output-based)",
				Description:   "Command injection in parameter '" + param + "': injected command output appeared in the response.",
				Severity:      SeverityCritical,
				Confidence:    ConfidenceHigh,
				Payload:       payload,
				Evidence:      "Command output detected in response",
				Scanner:       s.Name(),
				Parameter:     param,
				OWASPCategory: "A03:2021-Injection",
				Timestamp:     time.Now(),
			}, true
		}
	}
	return Finding{}, false
}

// timePayloads returns blind time-based command-injection payloads spanning
// separator styles and both Unix (sleep) and Windows (ping -n) delays.
func (s *CommandInjectionScanner) timePayloads(orig string) []string {
	sec := itoa(s.sleepSeconds())
	// Windows ping needs count = seconds + 1 to wait ~seconds.
	pings := itoa(s.sleepSeconds() + 1)
	return []string{
		orig + "; sleep " + sec,
		orig + "| sleep " + sec,
		orig + "& sleep " + sec,
		orig + "`sleep " + sec + "`",
		orig + "$(sleep " + sec + ")",
		orig + "%0asleep " + sec,
		orig + "; ping -c " + pings + " 127.0.0.1",
		orig + "& ping -n " + pings + " 127.0.0.1",
	}
}

// testTimeBlind detects blind command injection by timing an injected sleep,
// confirmed twice to reduce false positives.
func (s *CommandInjectionScanner) testTimeBlind(ctx context.Context, client *httpengine.Client, u *url.URL, query url.Values, param, orig string) (Finding, bool) {
	base := timeRequest(ctx, client, buildURL(u, query, param, orig))
	if base <= 0 || base > 2*time.Second {
		return Finding{}, false
	}
	threshold := time.Duration(s.sleepSeconds())*time.Second - time.Second

	for _, payload := range s.timePayloads(orig) {
		testURL := buildURL(u, query, param, payload)
		d1, d2, ok := confirmDelay(ctx, client, testURL, base, threshold)
		if !ok {
			continue
		}
		return Finding{
			URL:           testURL,
			Title:         "OS Command Injection (time-based blind)",
			Description:   "Blind command injection in parameter '" + param + "': an injected sleep delayed the response by roughly " + itoa(s.sleepSeconds()) + "s, confirmed twice.",
			Severity:      SeverityCritical,
			Confidence:    ConfidenceMedium,
			Payload:       payload,
			Evidence:      "delayed responses " + d1.Round(time.Millisecond).String() + " / " + d2.Round(time.Millisecond).String() + " vs fast baseline",
			Scanner:       s.Name(),
			Parameter:     param,
			OWASPCategory: "A03:2021-Injection",
			Timestamp:     time.Now(),
		}, true
	}
	return Finding{}, false
}

// detectCommandOutput checks for command execution indicators.
func (s *CommandInjectionScanner) detectCommandOutput(body string) bool {
	indicators := []string{
		"root:",
		"bin/bash",
		"total ",
		"drwx",
		"-rwx",
		"uid=",
		"gid=",
		"groups=",
		"[extensions]",
		"[fonts]",
		"Volume Serial Number",
		"Directory of",
	}

	for _, ind := range indicators {
		if strings.Contains(body, ind) {
			return true
		}
	}
	return false
}
