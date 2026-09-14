package wafbypass

import (
	"net/http"
)

func (b *Bypasser) getImpervaStrategies() []BypassStrategy {
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
			Description: "Adds X-Forwarded-For header",
			Apply: func(req *http.Request) error {
				req.Header.Set("X-Forwarded-For", b.generateRandomIP())
				return nil
			},
		},
		{
			Name:        "Referer Spoofing",
			Description: "Adds realistic Referer header",
			Apply: func(req *http.Request) error {
				referers := []string{
					"https://www.google.com/",
					"https://www.bing.com/",
					"https://search.yahoo.com/",
					"https://duckduckgo.com/",
				}
				req.Header.Set("Referer", referers[b.random.Intn(len(referers))])
				return nil
			},
		},
		{
			Name:        "Connection Header",
			Description: "Varies Connection header",
			Apply: func(req *http.Request) error {
				req.Header.Set("Connection", "keep-alive")
				return nil
			},
		},
	}
}
