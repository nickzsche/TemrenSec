// Package scanner provides active vulnerability scanners
package scanner

import (
	"context"
	"net/http"
	"time"

	"github.com/temren/pkg/httpengine"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

type Finding struct {
	URL           string
	Title         string
	Description   string
	Severity      Severity
	Confidence    Confidence
	Payload       string
	Evidence      string
	Scanner       string
	Timestamp     time.Time
	Request       string
	Response      string
	Parameter     string
	OWASPCategory string // 2021 tag (what individual scanners emit today)
	// OWASPCategory2025 is auto-filled by ScanEngine after a scan completes,
	// mapping the 2021 tag onto the corresponding 2025 category. Scanners
	// don't set this directly — see pkg/scanner/owasp.go for the mapping.
	OWASPCategory2025 string
	CVSSScore         float64
	// Verified is set to true when the deterministic proof layer
	// (pkg/scanner/proof.go) reproduced the vulnerability with a second,
	// independent request. Default false keeps this backward-compatible with
	// scanners and callers that don't know about verification.
	Verified bool
	// Proof carries a short, human-readable description of how the finding was
	// confirmed (or why it could not be). Empty when verification didn't run.
	Proof string
}

type Scanner interface {
	Name() string
	Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error)
}

func readBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()

	buf := make([]byte, 1024*1024)
	n, err := resp.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return nil, err
	}
	return buf[:n], nil
}
