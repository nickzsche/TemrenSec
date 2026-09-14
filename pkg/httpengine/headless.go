package httpengine

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

type HeadlessClient struct {
	browserURL string
	enabled    bool
	mu         sync.Mutex
	timeout    time.Duration
}

type HeadlessConfig struct {
	BrowserURL string
	Timeout    time.Duration
}

func DefaultHeadlessConfig() *HeadlessConfig {
	return &HeadlessConfig{
		BrowserURL: "",
		Timeout:    30 * time.Second,
	}
}

func NewHeadlessClient(cfg *HeadlessConfig) *HeadlessClient {
	if cfg == nil {
		cfg = DefaultHeadlessConfig()
	}
	return &HeadlessClient{
		browserURL: cfg.BrowserURL,
		enabled:    true,
		timeout:    cfg.Timeout,
	}
}

func (h *HeadlessClient) Fetch(ctx context.Context, pageURL string) (string, error) {
	if !h.enabled {
		return "", fmt.Errorf("headless client is disabled")
	}

	html, err := h.fetchWithChromedp(ctx, pageURL)
	if err != nil {
		return "", fmt.Errorf("headless fetch failed: %w", err)
	}
	return html, nil
}

func (h *HeadlessClient) FetchWithFallback(ctx context.Context, pageURL string, client *Client) (string, error) {
	html, err := h.Fetch(ctx, pageURL)
	if err == nil && html != "" {
		return html, nil
	}

	resp, err := client.Get(ctx, pageURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (h *HeadlessClient) Enable() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.enabled = true
}

func (h *HeadlessClient) Disable() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.enabled = false
}

func (h *HeadlessClient) IsEnabled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.enabled
}

func (h *HeadlessClient) fetchWithChromedp(ctx context.Context, pageURL string) (string, error) {
	return fetchRenderedHTML(ctx, pageURL, h.browserURL, h.timeout)
}

func ExtractLinksFromHTML(htmlContent string, baseURL string) []string {
	return ExtractLinks([]byte(htmlContent), baseURL)
}

func ExtractFormsFromHTML(htmlContent string, baseURL string) ([]Form, error) {
	parser := NewFormParser()
	return parser.ParseForms([]byte(htmlContent), baseURL)
}

func fetchRenderedHTML(ctx context.Context, pageURL, browserURL string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var allocCtx context.Context
	var allocCancel context.CancelFunc

	if browserURL != "" {
		allocCtx, allocCancel = chromedp.NewRemoteAllocator(ctx, browserURL)
	} else {
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
		)
		allocCtx, allocCancel = chromedp.NewExecAllocator(ctx, opts...)
	}
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	var html string
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(pageURL),
		chromedp.WaitReady("body"),
		chromedp.OuterHTML("html", &html),
	)
	if err != nil {
		return "", fmt.Errorf("chromedp execution failed: %w", err)
	}

	html = strings.ReplaceAll(html, "<script></script>", "")
	return strings.TrimSpace(html), nil
}