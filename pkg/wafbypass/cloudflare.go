package wafbypass

import (
	"net/http"
)

// getCloudflareStrategies returns Cloudflare-specific bypass techniques
func (b *Bypasser) getCloudflareStrategies() []BypassStrategy {
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
			Name:        "X-Forwarded-For Spoofing",
			Description: "Adds X-Forwarded-For header to bypass IP-based rules",
			Apply: func(req *http.Request) error {
				req.Header.Set("X-Forwarded-For", b.generateRandomIP())
				req.Header.Set("X-Real-IP", b.generateRandomIP())
				return nil
			},
		},
		{
			Name:        "Accept-Language Variation",
			Description: "Varies Accept-Language header",
			Apply: func(req *http.Request) error {
				languages := []string{"en-US,en;q=0.9", "en-GB,en;q=0.9", "tr-TR,tr;q=0.9,en;q=0.8", "de-DE,de;q=0.9", "fr-FR,fr;q=0.9"}
				req.Header.Set("Accept-Language", languages[b.random.Intn(len(languages))])
				return nil
			},
		},
		{
			Name:        "Accept-Encoding Variation",
			Description: "Varies Accept-Encoding header",
			Apply: func(req *http.Request) error {
				encodings := []string{"gzip, deflate, br", "gzip, deflate", "identity", "*"}
				req.Header.Set("Accept-Encoding", encodings[b.random.Intn(len(encodings))])
				return nil
			},
		},
		{
			Name:        "DNT Header",
			Description: "Adds Do Not Track header",
			Apply: func(req *http.Request) error {
				req.Header.Set("DNT", "1")
				return nil
			},
		},
		{
			Name:        "Sec-Fetch Headers",
			Description: "Adds Sec-Fetch headers",
			Apply: func(req *http.Request) error {
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				return nil
			},
		},
	}
}

// generateRandomIP generates a random IP address
func (b *Bypasser) generateRandomIP() string {
	return []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"1.1.1.1",
		"8.8.8.8",
	}[b.random.Intn(5)]
}
