package httpengine

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type ProxyConfig struct {
	URL      string
	Type     string
	Failures int
	MaxFails int
}

type ProxyRotator struct {
	proxies []*ProxyConfig
	mu      sync.RWMutex
	rand    *rand.Rand
}

func NewProxyRotator(proxyList, proxyType string) (*ProxyRotator, error) {
	if proxyList == "" {
		return nil, fmt.Errorf("proxy list is empty")
	}

	var entries []string

	if _, err := os.Stat(proxyList); err == nil {
		data, err := os.ReadFile(proxyList)
		if err != nil {
			return nil, fmt.Errorf("failed to read proxy file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				entries = append(entries, line)
			}
		}
	} else {
		entries = strings.Split(proxyList, ",")
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no proxies found")
	}

	pr := &ProxyRotator{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		pc := &ProxyConfig{
			MaxFails: 5,
		}

		parsedType := proxyType
		if strings.HasPrefix(entry, "socks5://") {
			parsedType = "socks5"
		} else if strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "https://") {
			parsedType = "http"
		}

		pc.Type = parsedType

		if strings.Contains(entry, "://") {
			pc.URL = entry
		} else {
			scheme := "http"
			if parsedType == "socks5" {
				scheme = "socks5"
			}
			pc.URL = scheme + "://" + entry
		}

		if _, err := url.Parse(pc.URL); err != nil {
			continue
		}

		pr.proxies = append(pr.proxies, pc)
	}

	if len(pr.proxies) == 0 {
		return nil, fmt.Errorf("no valid proxies found")
	}

	return pr, nil
}

func (pr *ProxyRotator) Next() *ProxyConfig {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	available := pr.availableProxies()
	if len(available) == 0 {
		return nil
	}

	return available[pr.rand.Intn(len(available))]
}

func (pr *ProxyRotator) MarkFailed(proxyURL string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for _, p := range pr.proxies {
		if p.URL == proxyURL {
			p.Failures++
			break
		}
	}
}

func (pr *ProxyRotator) MarkSuccess(proxyURL string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for _, p := range pr.proxies {
		if p.URL == proxyURL {
			p.Failures = 0
			break
		}
	}
}

func (pr *ProxyRotator) AvailableCount() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	return len(pr.availableProxies())
}

func (pr *ProxyRotator) TotalCount() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	return len(pr.proxies)
}

func (pr *ProxyRotator) BuildTransport(pc *ProxyConfig) (*http.Transport, error) {
	proxyURL, err := url.Parse(pc.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %s: %w", pc.URL, err)
	}

	if pc.Type == "socks5" {
		return buildSOCKS5Transport(proxyURL)
	}

	return buildHTTPProxyTransport(proxyURL), nil
}

func buildHTTPProxyTransport(proxyURL *url.URL) *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
		Proxy:               http.ProxyURL(proxyURL),
	}
}

func buildSOCKS5Transport(proxyURL *url.URL) (*http.Transport, error) {
	auth := &proxy.Auth{}
	if proxyURL.User != nil {
		auth.User = proxyURL.User.Username()
		pass, _ := proxyURL.User.Password()
		auth.Password = pass
	}

	dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer does not support DialContext")
	}

	return &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         contextDialer.DialContext,
	}, nil
}

func (pr *ProxyRotator) availableProxies() []*ProxyConfig {
	var available []*ProxyConfig
	for _, p := range pr.proxies {
		if p.Failures < p.MaxFails {
			available = append(available, p)
		}
	}
	return available
}

// UpstreamProxyConfig holds configuration for routing all traffic through
// an upstream proxy (e.g., Burp Suite, ZAP) for debugging and interception.
// This is distinct from ProxyRotator which provides outbound anonymity.
type UpstreamProxyConfig struct {
	URL      string
	Username string
	Password string
	Type     string
}

func NewUpstreamProxyConfig(proxyURL string) (*UpstreamProxyConfig, error) {
	if proxyURL == "" {
		return nil, fmt.Errorf("upstream proxy URL is empty")
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream proxy URL: %w", err)
	}

	cfg := &UpstreamProxyConfig{
		URL:  proxyURL,
		Type: "http",
	}

	if parsed.User != nil {
		cfg.Username = parsed.User.Username()
		cfg.Password, _ = parsed.User.Password()
	}

	if parsed.Scheme == "socks5" {
		cfg.Type = "socks5"
	}

	return cfg, nil
}

func (c *UpstreamProxyConfig) Transport() (*http.Transport, error) {
	parsed, err := url.Parse(c.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream proxy URL: %w", err)
	}

	if c.Type == "socks5" {
		return buildSOCKS5Transport(parsed)
	}

	transport := buildHTTPProxyTransport(parsed)

	if c.Username != "" {
		originalProxy := transport.Proxy
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			proxyURL, err := originalProxy(req)
			if err != nil {
				return nil, err
			}
			return proxyURL, nil
		}
	}

	return transport, nil
}

func (c *UpstreamProxyConfig) ApplyToClient(client *Client) error {
	transport, err := c.Transport()
	if err != nil {
		return err
	}
	client.Client.Transport = transport
	return nil
}