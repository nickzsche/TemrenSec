package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/temren/pkg/scanner"
)

type fakeProvider struct {
	system, user string
	resp         string
}

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Complete(ctx context.Context, system, user string) (string, error) {
	f.system, f.user = system, user
	return f.resp, nil
}

func TestTriageHappyPath(t *testing.T) {
	p := &fakeProvider{resp: `{"is_true_hit":true,"confidence":0.9,"reasoning":"clear","remediation":"sanitize"}`}
	e := New(p)
	v, err := e.Triage(context.Background(), scanner.Finding{Title: "SQLi"})
	if err != nil {
		t.Fatal(err)
	}
	if !v.IsTrueHit || v.Confidence < 0.8 || v.Reasoning != "clear" {
		t.Errorf("bad verdict: %+v", v)
	}
}

func TestTriageMarkdownFencedJSON(t *testing.T) {
	p := &fakeProvider{resp: "```json\n{\"is_true_hit\":false,\"confidence\":0.1,\"reasoning\":\"FP\",\"remediation\":\"n/a\"}\n```"}
	e := New(p)
	v, err := e.Triage(context.Background(), scanner.Finding{})
	if err != nil {
		t.Fatal(err)
	}
	if v.IsTrueHit || v.Confidence > 0.5 {
		t.Errorf("expected false positive verdict, got %+v", v)
	}
}

func TestNLQueryParsesScanners(t *testing.T) {
	p := &fakeProvider{resp: `{"targets":["https://x"],"scanners":["sqli","xss"]}`}
	e := New(p)
	q, err := e.NLQuery(context.Background(), "scan my login page for injections")
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Scanners) != 2 || q.Targets[0] != "https://x" {
		t.Errorf("parse failed: %+v", q)
	}
}

func TestFallbackSummaryNoProvider(t *testing.T) {
	e := New(nil)
	out, err := e.ExecutiveSummary(context.Background(), []scanner.Finding{
		{Severity: scanner.SeverityCritical}, {Severity: scanner.SeverityHigh},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "2") {
		t.Errorf("expected counts in fallback: %q", out)
	}
}

func TestExtractJSONUnwrapsFences(t *testing.T) {
	in := "Here is the data:\n```json\n{\"k\":1}\n```"
	out := extractJSON(in)
	if out != `{"k":1}` {
		t.Errorf("unexpected: %q", out)
	}
}
