package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// FileUploadBypassScanner posts multipart files with double extensions, NULL byte,
// and tricky Content-Types to detect naive validators.
type FileUploadBypassScanner struct {
	UploadURL string // explicit endpoint; if empty, scanner is a no-op
}

func NewFileUploadBypassScanner(uploadURL string) *FileUploadBypassScanner {
	return &FileUploadBypassScanner{UploadURL: uploadURL}
}

func (s *FileUploadBypassScanner) Name() string { return "File Upload Validation Bypass" }

type uploadCase struct {
	name  string
	field string
	body  []byte
	ctype string
	risk  string
}

func (s *FileUploadBypassScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	// No-op without an explicit upload endpoint. Blindly POSTing multipart
	// shells to every crawled URL flags any endpoint that returns 2xx (static
	// files, SPA routes) as "upload accepted" — pure false positives. Real
	// upload testing needs a known upload endpoint (set via UploadURL / a
	// discovered upload form).
	if s.UploadURL == "" {
		return nil, nil
	}
	endpoint := s.UploadURL
	jpegMagic := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	cases := []uploadCase{
		{name: "shell.php.jpg", field: "file", body: append(jpegMagic, []byte("<?php phpinfo(); ?>")...), ctype: "image/jpeg", risk: "double-extension shell"},
		{name: "shell.php\x00.jpg", field: "file", body: []byte("<?php phpinfo(); ?>"), ctype: "image/jpeg", risk: "null-byte truncation"},
		{name: "shell.phtml", field: "file", body: []byte("<?php echo 1; ?>"), ctype: "image/jpeg", risk: ".phtml mapped to PHP"},
		{name: "shell.svg", field: "file", body: []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), ctype: "image/svg+xml", risk: "SVG XSS"},
		{name: "../../etc/passwd", field: "file", body: []byte("hello"), ctype: "text/plain", risk: "path traversal in filename"},
	}
	var findings []Finding
	for _, c := range cases {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		part, err := w.CreateFormFile(c.field, c.name)
		if err != nil {
			continue
		}
		part.Write(c.body)
		w.Close()

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
		req.Header.Set("Content-Type", w.FormDataContentType())
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		// A 2xx alone is not proof of acceptance — a static endpoint returns 2xx
		// while ignoring the body. Require evidence the upload was actually
		// processed: the response echoes the filename, or carries an
		// upload-success indicator (stored path / URL / success flag).
		low := strings.ToLower(string(body))
		reflectsName := strings.Contains(low, strings.ToLower(strings.TrimSpace(c.name)))
		markers := []string{"\"url\"", "\"path\"", "\"filename\"", "\"location\"", "uploaded", "upload success", "\"success\":true", "file saved"}
		hasMarker := false
		for _, mk := range markers {
			if strings.Contains(low, mk) {
				hasMarker = true
				break
			}
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && (reflectsName || hasMarker) {
			findings = append(findings, Finding{
				URL: endpoint, Title: fmt.Sprintf("Upload Accepted: %s (%s)", c.name, c.risk),
				Description: "Server accepted an upload with content/extension pattern that commonly bypasses naive validators. Verify whether the file is stored, executable, or reflectable.",
				Severity:    SeverityHigh, Confidence: ConfidenceLow, Scanner: s.Name(),
				Payload:   c.name + " (" + c.ctype + ")",
				Evidence:  strings.TrimSpace(string(body[:minInt(160, len(body))])),
				Timestamp: time.Now(), OWASPCategory: "A04:2021-Insecure Design", CVSSScore: 7.5,
			})
		}
	}
	return findings, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
