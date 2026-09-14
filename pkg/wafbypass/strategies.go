package wafbypass

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (b *Bypasser) loadGenericStrategies() {
	b.strategies = []BypassStrategy{
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
	}
}

func ApplyPathEncoding(targetURL string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	path := u.Path
	encodedPath := strings.ReplaceAll(path, "/", "%2f")
	encodedPath = strings.ReplaceAll(encodedPath, ".", "%2e")

	// Build URL manually to avoid Go's url.URL.String() re-encoding % signs
	result := u.Scheme + "://" + u.Host + encodedPath
	if u.RawQuery != "" {
		result += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		result += "#" + u.Fragment
	}
	return result, nil
}

func ApplyCaseTampering(targetURL string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	path := u.Path
	var result strings.Builder
	for i, c := range path {
		if i%2 == 0 {
			result.WriteString(strings.ToUpper(string(c)))
		} else {
			result.WriteString(strings.ToLower(string(c)))
		}
	}
	
	u.Path = result.String()
	return u.String(), nil
}

func ApplyCommentInjection(targetURL string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	path := u.Path
	if len(path) > 2 {
		mid := len(path) / 2
		newPath := path[:mid] + "/**/" + path[mid:]
		u.Path = newPath
	}
	
	return u.String(), nil
}

func ApplyPathTraversal(targetURL string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	path := u.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	
	u.Path = "/../.." + path
	return u.String(), nil
}

func ApplyDoubleEncoding(targetURL string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	path := u.Path
	doubleEncoded := url.QueryEscape(url.QueryEscape(path))
	u.Path = doubleEncoded
	return u.String(), nil
}

func ApplyNullByteInjection(targetURL string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	if strings.Contains(targetURL, "?") {
		return targetURL + "%00", nil
	}
	
	u.Path = u.Path + "%00"
	return u.String(), nil
}

type URLMutation struct {
	Name        string
	Description string
	Mutate      func(string) (string, error)
}

func GetAllURLMutations() []URLMutation {
	return []URLMutation{
		{Name: "Path Encoding", Description: "URL encode path characters", Mutate: ApplyPathEncoding},
		{Name: "Case Tampering", Description: "Random case variation", Mutate: ApplyCaseTampering},
		{Name: "Comment Injection", Description: "Insert SQL-style comments", Mutate: ApplyCommentInjection},
		{Name: "Path Traversal", Description: "Add traversal sequences", Mutate: ApplyPathTraversal},
		{Name: "Double Encoding", Description: "Double URL encode", Mutate: ApplyDoubleEncoding},
		{Name: "Null Byte", Description: "Append null byte", Mutate: ApplyNullByteInjection},
	}
}

func MutateURL(targetURL string, mutation URLMutation) (string, error) {
	return mutation.Mutate(targetURL)
}

func GenerateAllMutations(targetURL string) ([]string, error) {
	mutations := GetAllURLMutations()
	results := make([]string, 0, len(mutations))
	
	for _, m := range mutations {
		mutated, err := MutateURL(targetURL, m)
		if err != nil {
			continue
		}
		results = append(results, mutated)
	}
	
	return results, nil
}

func FormatWAFError(wafType WAFType, blocked bool) string {
	if blocked {
		return fmt.Sprintf("WAF detected and blocked: %s", wafType)
	}
	return fmt.Sprintf("WAF detected but bypassed: %s", wafType)
}
