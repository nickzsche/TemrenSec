package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// SSRFCloudMetadataScanner probes likely SSRF sinks for cloud-metadata responses.
type SSRFCloudMetadataScanner struct{}

func NewSSRFCloudMetadataScanner() *SSRFCloudMetadataScanner { return &SSRFCloudMetadataScanner{} }

func (s *SSRFCloudMetadataScanner) Name() string { return "SSRF — Cloud Metadata" }

var ssrfTargets = []string{
	"http://169.254.169.254/latest/meta-data/",                       // AWS
	"http://169.254.169.254/computeMetadata/v1/?recursive=true",      // GCP (needs header but worth probing)
	"http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
	"http://metadata.google.internal/computeMetadata/v1/instance/",
	"http://100.100.100.200/latest/meta-data/", // Alibaba
	"http://169.254.169.254/openstack/latest/meta_data.json", // OpenStack
}

func (s *SSRFCloudMetadataScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	// Skip build artifacts entirely. JS/CSS/font URLs aren't SSRF sinks,
	// but their SPA-wildcard host happily returns 200 + HTML for any
	// query string we append, which the old scanner mistook for a
	// successful metadata exfil.
	if IsStaticAssetURL(target) {
		return nil, nil
	}

	candidates := []string{"url", "uri", "next", "redirect", "image", "callback", "feed", "host", "domain", "site"}
	var findings []Finding
	for _, p := range candidates {
		for _, meta := range ssrfTargets {
			full := target
			sep := "?"
			if strings.Contains(target, "?") {
				sep = "&"
			}
			full = full + sep + p + "=" + meta
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
			req.Header.Set("Metadata", "true")
			req.Header.Set("Metadata-Flavor", "Google")
			resp, err := client.Do(ctx, req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			ct := resp.Header.Get("Content-Type")
			resp.Body.Close()

			// Real metadata responses are short, plain-text or JSON —
			// never HTML. SPA catch-alls return 24 KB HTML that happens
			// to contain words like "instance-id" or "compute"; those
			// are FPs.
			if isHTMLResponse(ct, body) {
				continue
			}
			if !looksLikeRealMetadataResponse(body) {
				continue
			}

			findings = append(findings, Finding{
				URL:           full,
				Title:         "SSRF — Cloud Metadata Reachable",
				Description:   "Parameter forwarded a request to the cloud instance-metadata service. Attacker can exfiltrate IAM credentials.",
				Severity:      SeverityCritical,
				Confidence:    ConfidenceHigh,
				Scanner:       s.Name(),
				Parameter:     p,
				Payload:       meta,
				Timestamp:     time.Now(),
				OWASPCategory: "A10:2021-SSRF",
				CVSSScore:     9.8,
			})
		}
	}
	return findings, nil
}

// looksLikeRealMetadataResponse requires the response to look like an
// actual cloud-metadata service payload. Generic substring matches on
// words like "instance-id" or "compute" hit HTML routinely.
//
// AWS plain-text: 200, body is a newline-separated list ending in
//   `iam/`, `instance-id`, `placement/`, etc.
// AWS / Azure / GCP JSON: contains specific key combinations.
func looksLikeRealMetadataResponse(body []byte) bool {
	s := string(body)
	low := strings.ToLower(s)
	// AWS plain-text metadata listing
	if strings.Contains(s, "instance-id\n") || strings.HasPrefix(s, "ami-id\n") {
		return true
	}
	// AWS or Azure JSON response with structured creds
	if strings.Contains(low, `"accesskeyid"`) && strings.Contains(low, `"secretaccesskey"`) {
		return true
	}
	if strings.Contains(low, `"instanceid":"i-`) {
		return true
	}
	// GCP nested JSON
	if strings.Contains(low, `"projectid"`) && (strings.Contains(low, `"machinetype"`) || strings.Contains(low, `"serviceaccounts"`)) {
		return true
	}
	// Azure compute metadata
	if strings.Contains(low, `"compute":{`) && (strings.Contains(low, `"subscriptionid"`) || strings.Contains(low, `"vmid"`)) {
		return true
	}
	return false
}
