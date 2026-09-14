// Package spider provides a recursive web crawler
package spider

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/temren/pkg/httpengine"
)

// Result represents a crawled page result
type Result struct {
	URL      string
	Response *httpengine.Response
	Error    error
	Forms    []httpengine.Form
	Links    []string
	Depth    int
}

// Config holds spider configuration
type Config struct {
	MaxDepth      int
	MaxPages      int
	Concurrency   int
	SameDomain    bool
	ExcludeFilter []string // URL patterns to exclude
	IncludeFilter []string // URL patterns to include (whitelist)
	Delay         time.Duration
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		MaxDepth:    3,
		MaxPages:    100,
		Concurrency: 5,
		SameDomain:  true,
		Delay:       100 * time.Millisecond,
	}
}

// Spider is a recursive web crawler
type Spider struct {
	client  *httpengine.Client
	config  *Config
	visited map[string]bool
	mu      sync.RWMutex
	results chan Result
	wg      sync.WaitGroup
}

// New creates a new Spider instance
func New(client *httpengine.Client, cfg *Config) *Spider {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Spider{
		client:  client,
		config:  cfg,
		visited: make(map[string]bool),
		results: make(chan Result, 100),
	}
}

// Crawl starts crawling from the given URL
func (s *Spider) Crawl(ctx context.Context, startURL string) <-chan Result {
	s.wg.Add(1)
	go func() {
		s.crawl(ctx, startURL, 0)
		s.wg.Done()
	}()
	go func() {
		s.wg.Wait()
		close(s.results)
	}()
	return s.results
}

// crawl recursively crawls URLs
func (s *Spider) crawl(ctx context.Context, rawURL string, depth int) {
	// Check depth limit
	if depth > s.config.MaxDepth {
		return
	}

	// Normalize and check if visited
	normalizedURL := s.normalizeURL(rawURL)
	if normalizedURL == "" {
		return
	}

	s.mu.Lock()
	if s.visited[normalizedURL] {
		s.mu.Unlock()
		return
	}
	if len(s.visited) >= s.config.MaxPages {
		s.mu.Unlock()
		return
	}
	s.visited[normalizedURL] = true
	s.mu.Unlock()

	// Apply delay
	if s.config.Delay > 0 {
		time.Sleep(s.config.Delay)
	}

	// Make request
	start := time.Now()
	resp, err := s.client.Get(ctx, rawURL)
	if err != nil {
		select {
		case s.results <- Result{
			URL:   rawURL,
			Error: err,
			Depth: depth,
		}:
		case <-ctx.Done():
		}
		return
	}

	// Wrap response
	result := Result{
		URL: rawURL,
		Response: &httpengine.Response{
			Response:   resp,
			URL:        rawURL,
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Latency:    time.Since(start).Milliseconds(),
		},
		Depth: depth,
	}

	// Read body
	body, err := result.Response.ReadBody()
	if err != nil {
		select {
		case s.results <- result:
		case <-ctx.Done():
		}
		return
	}

	// Parse forms
	parser := httpengine.NewFormParser()
	forms, _ := parser.ParseForms(body, rawURL)
	result.Forms = forms

	// Extract links
	links := httpengine.ExtractLinks(body, rawURL)
	result.Links = links

	// Send result with context check
	select {
	case s.results <- result:
	case <-ctx.Done():
		return
	}

	// Crawl discovered links
	if depth < s.config.MaxDepth {
		startURLParsed, _ := url.Parse(rawURL)
		for _, link := range links {
			linkParsed, err := url.Parse(link)
			if err != nil {
				continue
			}

			// Same domain check
			if s.config.SameDomain && linkParsed.Host != startURLParsed.Host {
				continue
			}

			// Apply ExcludeFilter and IncludeFilter patterns
			if s.matchesFilter(link) {
				continue
			}

			s.wg.Add(1)
			go func(l string, d int) {
				s.crawl(ctx, l, d)
				s.wg.Done()
			}(link, depth+1)
		}
	}
}

// normalizeURL normalizes a URL for deduplication
func (s *Spider) normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Remove fragment
	u.Fragment = ""

	// Sort query parameters for consistent normalization
	if len(u.RawQuery) > 0 {
		queryParams := strings.Split(u.RawQuery, "&")
		sort.Strings(queryParams)
		u.RawQuery = strings.Join(queryParams, "&")
	}

	return u.String()
}

// matchesFilter checks if URL matches any exclude/include pattern
func (s *Spider) matchesFilter(rawURL string) bool {
	for _, pattern := range s.config.ExcludeFilter {
		matched, _ := regexp.MatchString(pattern, rawURL)
		if matched {
			return true
		}
	}

	if len(s.config.IncludeFilter) > 0 {
		matched := false
		for _, pattern := range s.config.IncludeFilter {
			m, _ := regexp.MatchString(pattern, rawURL)
			if m {
				matched = true
				break
			}
		}
		if !matched {
			return true // Excluded if doesn't match any include pattern
		}
	}

	return false
}

// GetVisited returns all visited URLs
func (s *Spider) GetVisited() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	urls := make([]string, 0, len(s.visited))
	for u := range s.visited {
		urls = append(urls, u)
	}
	return urls
}
