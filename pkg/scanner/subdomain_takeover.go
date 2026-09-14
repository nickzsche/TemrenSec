package scanner

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// SubdomainTakeoverScanner resolves the target host's CNAME; when it points at a
// well-known third-party host (GitHub Pages, S3, Heroku, ...) and that host
// responds with its "unclaimed resource" fingerprint, the subdomain can likely
// be taken over.
type SubdomainTakeoverScanner struct {
	Resolver *net.Resolver
}

func NewSubdomainTakeoverScanner() *SubdomainTakeoverScanner {
	return &SubdomainTakeoverScanner{Resolver: net.DefaultResolver}
}

func (s *SubdomainTakeoverScanner) Name() string { return "Subdomain Takeover" }

// takeoverSuffixes maps a CNAME suffix to a vendor. `contains` marks suffixes
// that appear mid-name (S3 website endpoints embed the region between
// "s3-website" and ".amazonaws.com"), everything else is a right-side suffix.
var takeoverSuffixes = []struct {
	service  string
	suffix   string
	contains bool
}{
	{"GitHub Pages", "github.io", false},
	{"GitHub Pages", "github.com", false},
	{"AWS S3", "s3.amazonaws.com", false},
	{"AWS S3", "s3-website", true},
	{"Heroku", "herokuapp.com", false},
	{"Heroku", "herokudns.com", false},
	{"Azure", "azurewebsites.net", false},
	{"Azure", "cloudapp.azure.com", false},
	{"Fastly", "fastly.net", false},
	{"Shopify", "shops.myshopify.com", false},
	{"Surge", "surge.sh", false},
	{"Netlify", "netlify.app", false},
	{"CloudFront", "cloudfront.net", false},
	{"Bitbucket", "bitbucket.io", false},
}

// matchServiceSuffix returns the vendor for a CNAME ending in a known service
// suffix, or "" if none match. Boundary-checked so "evilgithub.io" doesn't
// match "github.io".
func matchServiceSuffix(cname string) string {
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, s := range takeoverSuffixes {
		if s.contains {
			if strings.Contains(cname, "."+s.suffix) {
				return s.service
			}
		} else if cname == s.suffix || strings.HasSuffix(cname, "."+s.suffix) {
			return s.service
		}
	}
	return ""
}

// takeoverFingerprints holds the "this resource is not claimed" body markers
// each vendor serves for a dead/unregistered subdomain.
var takeoverFingerprints = []struct {
	service string
	matches []string
}{
	{"GitHub Pages", []string{"There isn't a GitHub Pages site here"}},
	{"AWS S3", []string{"NoSuchBucket", "The specified bucket does not exist"}},
	{"Heroku", []string{"No such app", "There's nothing here, yet"}},
	{"Azure", []string{"404 Web Site not found"}},
	{"Fastly", []string{"Fastly error: unknown domain"}},
	{"Netlify", []string{"Not Found"}},
	{"Shopify", []string{"Sorry, this shop is currently unavailable"}},
}

// fingerprintTakeover scans a response body for a takeover fingerprint and
// returns the matching vendor.
func fingerprintTakeover(body string) (service string, ok bool) {
	service, _, ok = matchTakeoverFingerprint(body)
	return service, ok
}

// matchTakeoverFingerprint is like fingerprintTakeover but also returns the
// matched marker text, used as evidence in the finding.
func matchTakeoverFingerprint(body string) (service, text string, ok bool) {
	lower := strings.ToLower(body)
	for _, f := range takeoverFingerprints {
		for _, m := range f.matches {
			if strings.Contains(lower, strings.ToLower(m)) {
				return f.service, m, true
			}
		}
	}
	return "", "", false
}

func (s *SubdomainTakeoverScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
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

	cnameService := matchServiceSuffix(cname)
	if cnameService == "" {
		return nil, nil
	}

	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, nil
	}
	body, _ := readBody(resp)

	service, fpText, ok := matchTakeoverFingerprint(string(body))
	if !ok || service != cnameService {
		return nil, nil
	}

	return []Finding{{
		URL:           target,
		Title:         "Subdomain Takeover (" + service + ")",
		Description:   "CNAME points to " + cname + " (" + service + ") but the service responds with its unclaimed-resource fingerprint, so the subdomain can likely be claimed by an attacker.",
		Severity:      SeverityHigh,
		Confidence:    ConfidenceHigh,
		Evidence:      fpText,
		Scanner:       s.Name(),
		Timestamp:     time.Now(),
		OWASPCategory: "A02 Security Misconfiguration",
		CVSSScore:     8.0,
	}}, nil
}
