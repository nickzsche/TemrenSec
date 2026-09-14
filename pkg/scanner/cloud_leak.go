package scanner

import (
	"context"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/temren/pkg/httpengine"
)

// CloudLeakScanner surfaces cloud-storage-bucket references in the
// response body. It used to also re-probe /.env, /.aws/credentials and
// similar paths with a body-substring matcher that lit up on every HTML
// page (because words like "AWS", "KEY", and "PASSWORD" appear in
// ordinary prose, JSON keys, and meta tags). Those probes are now
// owned by ExposedEndpointsScanner + SecretScanner with proper shape
// checks; this scanner focuses on bucket references only.
type CloudLeakScanner struct {
	cache sync.Map // host -> []Finding
}

func NewCloudLeakScanner() *CloudLeakScanner { return &CloudLeakScanner{} }

func (s *CloudLeakScanner) Name() string { return "Cloud Leak Detection" }

// Bucket references must include an actual bucket-host or bucket-path
// segment, not just the keyword. `bucket=` alone matches CSS classes
// like `bucket=list-button`, so we require it followed by an identifier.
var bucketPatterns = []struct {
	name  string
	regex *regexp.Regexp
}{
	{
		"S3 bucket reference (subdomain form)",
		regexp.MustCompile(`(?i)\bhttps?://[a-z0-9][a-z0-9.-]{2,62}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b`),
	},
	{
		"S3 bucket reference (path form)",
		regexp.MustCompile(`(?i)\bhttps?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[a-z0-9][a-z0-9.-]{2,62}/`),
	},
	{
		"S3 bucket reference (s3:// URI)",
		regexp.MustCompile(`(?i)\bs3://[a-z0-9][a-z0-9.-]{2,62}/`),
	},
	{
		"Azure Blob Storage reference",
		regexp.MustCompile(`(?i)\bhttps?://[a-z0-9-]+\.blob\.core\.windows\.net/[a-z0-9-]+/`),
	},
	{
		"Google Cloud Storage reference",
		regexp.MustCompile(`(?i)\bhttps?://storage\.googleapis\.com/[a-z0-9._-]{3,63}/`),
	},
	{
		"DigitalOcean Spaces reference",
		regexp.MustCompile(`(?i)\bhttps?://[a-z0-9-]+\.[a-z0-9-]+\.digitaloceanspaces\.com\b`),
	},
}

func (s *CloudLeakScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, nil
	}
	if cached, ok := s.cache.Load(u.Host); ok {
		return cached.([]Finding), nil
	}

	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err == nil {
		body, _ := readBody(resp)
		resp.Body.Close()
		bodyStr := string(body)

		seen := make(map[string]struct{})
		for _, bp := range bucketPatterns {
			for _, match := range bp.regex.FindAllString(bodyStr, -1) {
				if _, dup := seen[match]; dup {
					continue
				}
				seen[match] = struct{}{}
				findings = append(findings, Finding{
					URL:         target,
					Title:       "Cloud bucket reference: " + bp.name,
					Description: "Page references a cloud-storage URL. Review whether the bucket is intentionally public.",
					Severity:    SeverityLow,
					Confidence:  ConfidenceLow,
					Evidence:    match,
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
			}
		}
	}

	s.cache.Store(u.Host, findings)
	return findings, nil
}
