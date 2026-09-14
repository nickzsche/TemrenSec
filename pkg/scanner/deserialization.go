package scanner

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// DeserializationScanner posts known-bad serialized blobs (Java/PHP/Python) to detect
// insecure deserialization endpoints by error message leakage.
type DeserializationScanner struct{}

func NewDeserializationScanner() *DeserializationScanner { return &DeserializationScanner{} }

func (s *DeserializationScanner) Name() string { return "Insecure Deserialization" }

// Magic-byte markers — none are weaponized; we look for deserializer errors.
var deserBlobs = map[string][]byte{
	"java-serialized":  {0xAC, 0xED, 0x00, 0x05, 0x73, 0x72},
	"php-serialized":   []byte(`O:8:"stdClass":1:{s:1:"a";s:1:"b";}`),
	"python-pickle":    {0x80, 0x04, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00},
	"ruby-marshal":     {0x04, 0x08, 0x6f, 0x3a},
	"dotnet-binaryfmt": {0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00},
}

var deserErrors = []string{
	"java.io.invalidclass",
	"streamcorruptedexception",
	"unserialize()",
	"pickle.unpicklingerror",
	"binaryformatter",
	"marshal data too short",
	"yaml.constructor",
}

func (s *DeserializationScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding
	for label, blob := range deserBlobs {
		b64 := base64.StdEncoding.EncodeToString(blob)
		for _, body := range []string{string(blob), b64} {
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader([]byte(body)))
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := client.Do(ctx, req)
			if err != nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
			resp.Body.Close()
			low := strings.ToLower(string(respBody))
			for _, marker := range deserErrors {
				if strings.Contains(low, marker) {
					findings = append(findings, Finding{
						URL:           target,
						Title:         "Insecure Deserialization Endpoint (" + label + ")",
						Description:   "Endpoint attempted to deserialize untrusted bytes and surfaced a deserializer error. This often enables remote code execution via gadget chains.",
						Severity:      SeverityCritical,
						Confidence:    ConfidenceMedium,
						Payload:       label,
						Evidence:      marker,
						Scanner:       s.Name(),
						Timestamp:     time.Now(),
						OWASPCategory: "A08:2021-Software and Data Integrity Failures",
						CVSSScore:     9.8,
					})
					return findings, nil
				}
			}
		}
	}
	return findings, nil
}
