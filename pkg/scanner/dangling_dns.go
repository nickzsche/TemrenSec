package scanner

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// DanglingDNSScanner inspects the CNAME chain of the target host and flags well-known
// "danglable" providers — when the CNAME points to an unclaimed bucket the attacker
// can register, hijacking the subdomain.
type DanglingDNSScanner struct {
	Resolver *net.Resolver
}

func NewDanglingDNSScanner() *DanglingDNSScanner { return &DanglingDNSScanner{Resolver: net.DefaultResolver} }

func (s *DanglingDNSScanner) Name() string { return "Subdomain Takeover (Dangling DNS)" }

var takeoverPatterns = []struct {
	suffix string
	vendor string
}{
	{".github.io.", "GitHub Pages"},
	{".herokuapp.com.", "Heroku"},
	{".azurewebsites.net.", "Azure Web Apps"},
	{".cloudfront.net.", "CloudFront"},
	{".s3.amazonaws.com.", "S3"},
	{".s3-website", "S3 Website"},
	{".trafficmanager.net.", "Azure Traffic Manager"},
	{".elasticbeanstalk.com.", "Elastic Beanstalk"},
	{".storage.googleapis.com.", "GCS"},
	{".pantheonsite.io.", "Pantheon"},
	{".readthedocs.io.", "Read the Docs"},
	{".myshopify.com.", "Shopify"},
	{".firebaseapp.com.", "Firebase"},
	{".surge.sh.", "Surge"},
	{".tumblr.com.", "Tumblr"},
}

func (s *DanglingDNSScanner) Scan(ctx context.Context, target string, _ *httpengine.Client) ([]Finding, error) {
	host := target
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/:"); i > 0 {
		host = host[:i]
	}
	cname, err := s.Resolver.LookupCNAME(ctx, host)
	if err != nil || cname == "" {
		return nil, nil
	}
	for _, t := range takeoverPatterns {
		if strings.HasSuffix(cname, t.suffix) || strings.Contains(cname, t.suffix) {
			// Resolve target host: if NXDOMAIN despite CNAME, that's dangling.
			if _, lookupErr := s.Resolver.LookupHost(ctx, host); lookupErr != nil {
				return []Finding{{
					URL: target, Title: "Likely Subdomain Takeover (" + t.vendor + ")",
					Description: "Host has a CNAME pointing to " + cname + " but the target does not resolve. An attacker can register the unclaimed " + t.vendor + " resource and serve content as your subdomain.",
					Severity: SeverityCritical, Confidence: ConfidenceHigh, Scanner: s.Name(),
					Evidence: "CNAME=" + cname, Timestamp: time.Now(),
					OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 9.0,
				}}, nil
			}
			return []Finding{{
				URL: target, Title: "Subdomain points to " + t.vendor + " (informational)",
				Description: "CNAME=" + cname + ". Confirm the resource is owned by your org to prevent future takeover.",
				Severity: SeverityInfo, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "informational",
			}}, nil
		}
	}
	return nil, nil
}
