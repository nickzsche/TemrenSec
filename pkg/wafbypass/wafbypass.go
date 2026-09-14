// Package wafbypass provides WAF bypass techniques for various WAF vendors
package wafbypass

import (
	"math/rand"
	"net/http"
	"time"
)

// WAFType represents different WAF vendors
type WAFType string

const (
	WAFCloudflare WAFType = "cloudflare"
	WAFAkamai     WAFType = "akamai"
	WAFImperva    WAFType = "imperva"
	WAFAWS        WAFType = "aws"
	WAFGeneric    WAFType = "generic"
)

// BypassStrategy defines a single bypass technique
type BypassStrategy struct {
	Name        string
	Description string
	Apply       func(*http.Request) error
}

// Bypasser manages WAF bypass techniques
type Bypasser struct {
	wafType    WAFType
	strategies []BypassStrategy
	random     *rand.Rand
}

// NewBypasser creates a new WAF bypasser for the specified WAF type
func NewBypasser(wafType WAFType) *Bypasser {
	b := &Bypasser{
		wafType: wafType,
		random:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	b.loadStrategies()
	return b
}

// NewGenericBypasser creates a bypasser with all generic techniques
func NewGenericBypasser() *Bypasser {
	b := &Bypasser{
		wafType: WAFGeneric,
		random:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	b.loadGenericStrategies()
	return b
}

// loadStrategies loads bypass strategies based on WAF type
func (b *Bypasser) loadStrategies() {
	switch b.wafType {
	case WAFCloudflare:
		b.strategies = b.getCloudflareStrategies()
	case WAFAkamai:
		b.strategies = b.getAkamaiStrategies()
	case WAFImperva:
		b.strategies = b.getImpervaStrategies()
	case WAFAWS:
		b.strategies = b.getAWSStrategies()
	default:
		b.loadGenericStrategies()
	}
}

// ApplyRandom applies a random bypass strategy to the request
func (b *Bypasser) ApplyRandom(req *http.Request) error {
	if len(b.strategies) == 0 {
		return nil
	}
	strategy := b.strategies[b.random.Intn(len(b.strategies))]
	return strategy.Apply(req)
}

// ApplyAll applies all bypass strategies sequentially
func (b *Bypasser) ApplyAll(req *http.Request) error {
	for _, strategy := range b.strategies {
		if err := strategy.Apply(req); err != nil {
			return err
		}
	}
	return nil
}

// GetStrategies returns all available strategies
func (b *Bypasser) GetStrategies() []BypassStrategy {
	return b.strategies
}

// WAFDetector detects WAF type from response
func WAFDetector(resp *http.Response) WAFType {
	if resp == nil {
		return WAFGeneric
	}

	// Check headers
	server := resp.Header.Get("Server")
	via := resp.Header.Get("Via")
	xCache := resp.Header.Get("X-Cache")
	cfRay := resp.Header.Get("CF-RAY")
	xAkkamai := resp.Header.Get("X-Akamai-Request-BC")
	xWAF := resp.Header.Get("X-WAF")

	// Cloudflare detection
	if cfRay != "" || server == "cloudflare" {
		return WAFCloudflare
	}

	// Akamai detection
	if xAkkamai != "" || via == "Akamai" {
		return WAFAkamai
	}

	// Imperva/Incapsula detection
	if xWAF != "" || server == "Incapsula" {
		return WAFImperva
	}

	// AWS WAF detection
	if server == "awselb/2.0" || xCache == "Error from cloudfront" {
		return WAFAWS
	}

	return WAFGeneric
}

// UserAgents for rotation
var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
}

// GetRandomUserAgent returns a random user agent
func GetRandomUserAgent() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return UserAgents[r.Intn(len(UserAgents))]
}
