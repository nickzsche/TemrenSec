// Package httpengine provides a fast HTTP client with rate limiting
package httpengine

import (
	"context"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/temren/pkg/wafbypass"
	"golang.org/x/time/rate"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
}

const (
	maxBackoff      = 60 * time.Second
	initialBackoff  = 1 * time.Second
	defaultJitterMin = 100 * time.Millisecond
	defaultJitterMax = 500 * time.Millisecond
	maxRetries      = 5
)

type Client struct {
	*http.Client
	limiter        *rate.Limiter
	UserAgent      string
	baseRate       int
	perHostRate    int
	consecutive429 int
	mu             sync.Mutex
	isHoneypot     bool
	bypasser       *wafbypass.Bypasser
	useBypass      bool
	authConfig     *AuthConfig

	// hostLimiters holds a per-host rate.Limiter keyed by URL host (no port).
	// Created lazily on first request to a host. The global `limiter` still
	// applies as the overall budget — per-host is a *floor* (we wait on
	// both). Without this, 80 scanners × 500 URLs against one target would
	// fan out limited only by the global limiter, which sums across hosts.
	hostLimiters sync.Map

	proxyRotator *ProxyRotator
	torDialer    *TorDialer
	rand         *rand.Rand

	jitterMin   time.Duration
	jitterMax   time.Duration
	rotateUA    bool
	backoffSeq  int
	lastBackoff time.Duration
}

type Config struct {
	Timeout         time.Duration
	MaxRedirects    int
	RateLimit       int
	// PerHostRate caps requests/sec to any single host. Defaults to
	// RateLimit if zero — i.e. one host can burn the whole budget,
	// which matches the pre-multi-host behaviour. Lower this (e.g. 5)
	// when scanning targets you don't own.
	PerHostRate     int
	UserAgent       string
	FollowRedirects bool
	EnableBypass    bool
	WAFType         wafbypass.WAFType

	ProxyList   string
	ProxyType   string
	TorEnabled  bool
	TorConfig   *TorConfig
	JitterMin   time.Duration
	JitterMax   time.Duration
	RotateUA    bool
}

func DefaultConfig() *Config {
	return &Config{
		Timeout:         30 * time.Second,
		MaxRedirects:    10,
		RateLimit:       10,
		UserAgent:       "TemrenSec/1.0 (Security Scanner)",
		FollowRedirects: true,
		JitterMin:       defaultJitterMin,
		JitterMax:       defaultJitterMax,
	}
}

func NewClient(cfg *Config) *Client {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}

	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	perHost := cfg.PerHostRate
	if perHost <= 0 {
		perHost = cfg.RateLimit
	}
	c := &Client{
		Client:      client,
		limiter:     rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit),
		UserAgent:   cfg.UserAgent,
		baseRate:    cfg.RateLimit,
		perHostRate: perHost,
		useBypass:   cfg.EnableBypass,
		rand:        rand.New(rand.NewSource(time.Now().UnixNano())),
		jitterMin:   cfg.JitterMin,
		jitterMax:   cfg.JitterMax,
		rotateUA:    cfg.RotateUA,
	}

	if cfg.JitterMin == 0 {
		c.jitterMin = defaultJitterMin
	}
	if cfg.JitterMax == 0 {
		c.jitterMax = defaultJitterMax
	}

	if cfg.EnableBypass {
		if cfg.WAFType != "" {
			c.bypasser = wafbypass.NewBypasser(cfg.WAFType)
		} else {
			c.bypasser = wafbypass.NewGenericBypasser()
		}
	}

	if cfg.ProxyList != "" {
		pr, err := NewProxyRotator(cfg.ProxyList, cfg.ProxyType)
		if err == nil {
			c.proxyRotator = pr
		}
	}

	if cfg.TorEnabled {
		td, err := NewTorDialer(cfg.TorConfig)
		if err == nil {
			c.torDialer = td
			c.Client.Transport = td.Transport()
		}
	}

	return c
}

func (c *Client) Wait(ctx context.Context) error {
	return c.limiter.Wait(ctx)
}

// hostLimiter lazily creates and returns the per-host rate.Limiter.
func (c *Client) hostLimiter(host string) *rate.Limiter {
	if host == "" {
		return c.limiter
	}
	if v, ok := c.hostLimiters.Load(host); ok {
		return v.(*rate.Limiter)
	}
	r := c.perHostRate
	if r <= 0 {
		r = c.baseRate
	}
	l := rate.NewLimiter(rate.Limit(r), r)
	actual, _ := c.hostLimiters.LoadOrStore(host, l)
	return actual.(*rate.Limiter)
}

// WaitForHost gates a request on BOTH the global and the per-host budget.
// The global limiter is the overall ceiling; the per-host limiter prevents
// a single target from absorbing the entire budget when many scanners run
// against it in parallel.
func (c *Client) WaitForHost(ctx context.Context, host string) error {
	if err := c.limiter.Wait(ctx); err != nil {
		return err
	}
	return c.hostLimiter(host).Wait(ctx)
}

func (c *Client) AdjustRate(statusCode int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if statusCode == 429 {
		c.consecutive429++
		if c.consecutive429 >= 3 {
			c.isHoneypot = true
			// Trigger egress rotation: ask the proxy/Tor provider for a
			// fresh identity. Best-effort — direct dial is a no-op.
			if c.torDialer != nil && c.torDialer.IsEnabled() {
				_ = c.torDialer.RenewIdentity()
			}
		}

		newRate := float64(c.baseRate) * math.Pow(0.5, float64(c.consecutive429))
		if newRate < 0.5 {
			newRate = 0.5
		}
		c.limiter.SetLimit(rate.Limit(newRate))
		c.rotateUserAgent()
	} else {
		c.consecutive429 = 0
		if c.limiter.Limit() < rate.Limit(c.baseRate) {
			newRate := float64(c.baseRate)
			c.limiter.SetLimit(rate.Limit(newRate))
		}
	}
}

func (c *Client) rotateUserAgent() {
	idx := c.rand.Intn(len(userAgents))
	c.UserAgent = userAgents[idx]
}

func (c *Client) IsHoneypot() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isHoneypot
}

func (c *Client) ResetHoneypot() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isHoneypot = false
	c.consecutive429 = 0
}

func (c *Client) applyJitter() {
	if c.jitterMin > 0 || c.jitterMax > 0 {
		jitterRange := c.jitterMax - c.jitterMin
		delay := c.jitterMin + time.Duration(c.rand.Int63n(int64(jitterRange)))
		time.Sleep(delay)
	}
}

func (c *Client) calculateBackoff(retryAfter string) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	if retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
			backoff := time.Duration(seconds) * time.Second
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			c.lastBackoff = backoff
			return backoff
		}
	}

	backoff := initialBackoff * time.Duration(1<<uint(c.backoffSeq))
	if backoff > maxBackoff {
		backoff = maxBackoff
	}

	c.backoffSeq++
	c.lastBackoff = backoff
	return backoff
}

func (c *Client) resetBackoff() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backoffSeq = 0
	c.lastBackoff = 0
}

func (c *Client) selectTransport() (*http.Transport, string) {
	if c.torDialer != nil && c.torDialer.IsEnabled() {
		return c.torDialer.Transport(), "tor"
	}

	if c.proxyRotator != nil {
		pc := c.proxyRotator.Next()
		if pc != nil {
			transport, err := c.proxyRotator.BuildTransport(pc)
			if err == nil {
				return transport, pc.URL
			}
		}
	}

	return nil, ""
}

func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error

	// Resolve host once for per-host rate limiting. req.URL.Host includes
	// :port, which we keep — different ports on the same host are
	// independent budgets (matches what a target operator would expect).
	host := ""
	if req.URL != nil {
		host = req.URL.Host
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Per-host + global budget. Returns the ctx error on cancellation.
		if err := c.WaitForHost(ctx, host); err != nil {
			return nil, err
		}

		c.applyJitter()

		if c.rotateUA || req.Header.Get("User-Agent") == "" {
			c.mu.Lock()
			ua := c.UserAgent
			c.mu.Unlock()
			req.Header.Set("User-Agent", ua)
		}

		if c.authConfig != nil {
			c.authConfig.Apply(req)
		}

		if c.useBypass && c.bypasser != nil {
			c.bypasser.ApplyRandom(req)
		}

		transport, proxyID := c.selectTransport()
		if transport != nil {
			c.Client.Transport = transport
		}

		resp, err := c.Client.Do(req.WithContext(ctx))
		if err != nil {
			if proxyID != "" && c.proxyRotator != nil {
				c.proxyRotator.MarkFailed(proxyID)
			}
			lastErr = err
			continue
		}

		if proxyID != "" && c.proxyRotator != nil {
			c.proxyRotator.MarkSuccess(proxyID)
		}

		c.AdjustRate(resp.StatusCode)

		if resp.StatusCode == 429 {
			retryAfter := resp.Header.Get("Retry-After")
			backoff := c.calculateBackoff(retryAfter)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}

			c.rotateUserAgent()
			continue
		}

		c.resetBackoff()
		return resp, nil
	}

	return nil, lastErr
}

func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}

func (c *Client) Post(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(ctx, req)
}

func (c *Client) EnableBypass() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.useBypass = true
	if c.bypasser == nil {
		c.bypasser = wafbypass.NewGenericBypasser()
	}
}

func (c *Client) DisableBypass() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.useBypass = false
}

func (c *Client) SetAuth(config *AuthConfig) { c.authConfig = config }

func (c *Client) SetWAFType(wafType wafbypass.WAFType) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bypasser = wafbypass.NewBypasser(wafType)
}

func (c *Client) SetProxyRotator(pr *ProxyRotator) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.proxyRotator = pr
}

func (c *Client) SetTorDialer(td *TorDialer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.torDialer = td
	if td != nil && td.IsEnabled() {
		c.Client.Transport = td.Transport()
	}
}

func (c *Client) RenewTorIdentity() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.torDialer == nil {
		return nil
	}
	return c.torDialer.RenewIdentity()
}