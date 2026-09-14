package httpengine

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Form represents an HTML form
type Form struct {
	Action string            // Form action URL
	Method string            // GET or POST
	Fields map[string]string // Form field name -> default value
}

// FormParser extracts forms from HTML
type FormParser struct{}

// NewFormParser creates a new form parser
func NewFormParser() *FormParser {
	return &FormParser{}
}

// ParseForms extracts all forms from HTML content
func (p *FormParser) ParseForms(body []byte, baseURL string) ([]Form, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}

	var forms []Form
	var currentForm *Form

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			currentForm = &Form{
				Method: "GET",
				Fields: make(map[string]string),
			}

			for _, attr := range n.Attr {
				switch attr.Key {
				case "action":
					currentForm.Action = p.resolveURL(attr.Val, baseURL)
				case "method":
					currentForm.Method = strings.ToUpper(attr.Val)
				}
			}
		}

		// Parse input fields
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea" || n.Data == "select") {
			if currentForm != nil {
				name, value := "", ""
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "value":
						value = attr.Val
					}
				}
				if name != "" {
					currentForm.Fields[name] = value
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}

		// Form closing tag
		if n.Type == html.ElementNode && n.Data == "form" && currentForm != nil {
			forms = append(forms, *currentForm)
			currentForm = nil
		}
	}

	traverse(doc)
	return forms, nil
}

// resolveURL resolves relative URLs to absolute
func (p *FormParser) resolveURL(href, base string) string {
	if href == "" {
		return base
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return href
	}

	hrefURL, err := url.Parse(href)
	if err != nil {
		return href
	}

	return baseURL.ResolveReference(hrefURL).String()
}

// ExtractLinks extracts all links from HTML content
func ExtractLinks(body []byte, baseURL string) []string {
	// Regex patterns for links
	linkRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	srcRegex := regexp.MustCompile(`src=["']([^"']+)["']`)

	links := make(map[string]bool)
	baseURLParsed, _ := url.Parse(baseURL)

	// Extract href links
	for _, match := range linkRegex.FindAllStringSubmatch(string(body), -1) {
		if len(match) > 1 {
			link := resolveLink(match[1], baseURLParsed)
			if link != "" {
				links[link] = true
			}
		}
	}

	// Extract src links
	for _, match := range srcRegex.FindAllStringSubmatch(string(body), -1) {
		if len(match) > 1 {
			link := resolveLink(match[1], baseURLParsed)
			if link != "" {
				links[link] = true
			}
		}
	}

	// Convert to slice
	result := make([]string, 0, len(links))
	for link := range links {
		result = append(result, link)
	}

	return result
}

// resolveLink resolves a link to absolute URL
func resolveLink(href string, baseURL *url.URL) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") {
		return ""
	}

	hrefURL, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := baseURL.ResolveReference(hrefURL)

	// Only return http/https URLs
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}

	return resolved.String()
}
