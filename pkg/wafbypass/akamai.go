package wafbypass

import (
	"net/http"
)

// getAkamaiStrategies returns Akamai-specific bypass techniques
func (b *Bypasser) getAkamaiStrategies() []BypassStrategy {
	return []BypassStrategy{
		{
			Name:        "User-Agent Rotation",
			Description: "Rotates through different user agents",
			Apply: func(req *http.Request) error {
				req.Header.Set("User-Agent", GetRandomUserAgent())
				return nil
			},
		},
		{
			Name:        "Akamai-Client-IP Spoofing",
			Description: "Spoofs Akamai-Client-IP header",
			Apply: func(req *http.Request) error {
				req.Header.Set("Akamai-Client-IP", b.generateRandomIP())
				req.Header.Set("True-Client-IP", b.generateRandomIP())
				return nil
			},
		},
		{
			Name:        "X-Forwarded-For Chain",
			Description: "Adds multiple IPs to X-Forwarded-For",
			Apply: func(req *http.Request) error {
				chain := b.generateRandomIP() + ", " + b.generateRandomIP() + ", " + b.generateRandomIP()
				req.Header.Set("X-Forwarded-For", chain)
				return nil
			},
		},
		{
			Name:        "Pragma No-Cache",
			Description: "Adds Pragma no-cache header",
			Apply: func(req *http.Request) error {
				req.Header.Set("Pragma", "no-cache")
				req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
				return nil
			},
		},
		{
			Name:        "Accept Header Variation",
			Description: "Varies Accept header slightly",
			Apply: func(req *http.Request) error {
				accepts := []string{
					"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
					"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
					"text/html,application/xhtml+xml,application/xml;q=0.9",
				}
				req.Header.Set("Accept", accepts[b.random.Intn(len(accepts))])
				return nil
			},
		},
	}
}
