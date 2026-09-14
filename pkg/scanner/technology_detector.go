package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"strings"
	"time"
)

// TechnologyDetector identifies technologies used
type TechnologyDetector struct{}

func NewTechnologyDetector() *TechnologyDetector {
	return &TechnologyDetector{}
}

func (s *TechnologyDetector) Name() string {
	return "Technology Detection"
}

func (s *TechnologyDetector) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err != nil {
		return findings, nil
	}

	body, _ := readBody(resp)
	resp.Body.Close()
	bodyStr := string(body)
	headers := resp.Header

	technologies := map[string]string{
		"WordPress":       "wp-|wp-content|wp-includes",
		"jQuery":          "jquery",
		"React":           "react|react-dom|__react",
		"Vue.js":          "vue|vuejs|__vue",
		"Angular":         "angular|ng-app|ng-controller",
		"Bootstrap":       "bootstrap",
		"Foundation":      "foundation",
		"Tailwind":        "tailwind",
		"Next.js":         "_next/static",
		"Nuxt.js":         "__nuxt",
		"Laravel":         "laravel_session|XSRF-TOKEN",
		"Django":          "csrftoken|django",
		"Flask":           "flask",
		"Express":         "express",
		"Node.js":         "node|express",
		"PHP":             "PHPSESSID|PHP",
		"Apache":          "Apache",
		"Nginx":           "nginx",
		"Cloudflare":      "cf-ray|__cfduid",
		"Amazon AWS":      "aws-",
		"Google Cloud":    "google",
		"Microsoft Azure": "azure",
		"WooCommerce":     "woocommerce",
		"Shopify":         "shopify",
		"Magento":         "mage-",
		"Drupal":          "drupal",
		"Joomla":          "joomla",
	}

	for tech, pattern := range technologies {
		if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(pattern)) {
			findings = append(findings, Finding{
				URL:         target,
				Title:       "Technology Detected: " + tech,
				Description: "Technology stack identified: " + tech,
				Severity:    SeverityInfo,
				Confidence:  ConfidenceLow,
				Evidence:    "Pattern matched in response",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	serverHeader := headers.Get("Server")
	if serverHeader != "" {
		findings = append(findings, Finding{
			URL:         target,
			Title:       "Web Server: " + serverHeader,
			Description: "Server header reveals web server information",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceHigh,
			Evidence:    serverHeader,
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	xPoweredBy := headers.Get("X-Powered-By")
	if xPoweredBy != "" {
		findings = append(findings, Finding{
			URL:         target,
			Title:       "Powered By: " + xPoweredBy,
			Description: "Technology stack revealed via X-Powered-By header",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceHigh,
			Evidence:    xPoweredBy,
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

