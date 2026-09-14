package scanner

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/temren/pkg/httpengine"
)

// PostMessageScanner statically inspects HTML/JS for postMessage handlers that omit an origin check.
type PostMessageScanner struct{}

func NewPostMessageScanner() *PostMessageScanner { return &PostMessageScanner{} }

func (s *PostMessageScanner) Name() string { return "postMessage Missing Origin Check" }

var addEvtListener = regexp.MustCompile(`addEventListener\s*\(\s*["']message["']\s*,\s*([A-Za-z_$][\w$]*)`)
var inlineHandler = regexp.MustCompile(`window\.onmessage\s*=`)
var originCheck = regexp.MustCompile(`event\.origin|e\.origin|\.origin\s*===|\.origin\s*==`)

func (s *PostMessageScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	resp.Body.Close()
	str := string(body)
	hasHandler := addEvtListener.MatchString(str) || inlineHandler.MatchString(str)
	if !hasHandler {
		return nil, nil
	}
	if originCheck.MatchString(str) {
		return nil, nil
	}
	return []Finding{{
		URL: target, Title: "postMessage handler without origin check",
		Description: "JavaScript registers a message handler but no origin equality check is detected. Any iframe / window.open can deliver hostile messages.",
		Severity: SeverityHigh, Confidence: ConfidenceMedium, Scanner: s.Name(),
		Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 7.5,
	}}, nil
}
