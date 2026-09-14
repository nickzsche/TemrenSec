package wafbypass

import (
	"net/http"
)

func (b *Bypasser) getAWSStrategies() []BypassStrategy {
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
			Name:        "X-Forwarded-For Chain",
			Description: "Adds multiple IPs to X-Forwarded-For",
			Apply: func(req *http.Request) error {
				chain := b.generateRandomIP() + ", " + b.generateRandomIP()
				req.Header.Set("X-Forwarded-For", chain)
				req.Header.Set("X-Forwarded-Host", "aws.amazon.com")
				return nil
			},
		},
		{
			Name:        "CloudFront Headers",
			Description: "Adds CloudFront-specific headers",
			Apply: func(req *http.Request) error {
				req.Header.Set("CloudFront-Viewer-Country", "US")
				req.Header.Set("CloudFront-Is-Tablet-Viewer", "false")
				req.Header.Set("CloudFront-Is-Mobile-Viewer", "false")
				req.Header.Set("CloudFront-Is-Desktop-Viewer", "true")
				return nil
			},
		},
	}
}
