package httpengine

import (
	"net/http"
)

// EgressProvider abstracts how outbound requests reach the target — direct
// dial, rotating HTTP proxies, SOCKS5 list, Tor, or a residential
// provider shim. Scanners don't care; they just call Client.Do and the
// Client picks a Transport per request via selectTransport.
//
// Rotate is called by the client when it detects pressure (3 consecutive
// 429s, honeypot suspicion, etc.) so a provider can swap IP/session.
// Direct providers return nil from Rotate harmlessly.
type EgressProvider interface {
	// Transport returns the *http.Transport (and a stable proxy ID for
	// success/failure accounting) to use for the next request. May return
	// (nil, "") to fall through to the default client transport.
	Transport() (*http.Transport, string)
	// MarkResult lets the provider track which proxy succeeded/failed so
	// it can rotate away from broken endpoints.
	MarkResult(proxyID string, success bool)
	// Rotate is called when the client wants a fresh egress identity
	// (e.g. after honeypot detection). Returns nil if the provider has
	// nothing to rotate (direct dial, single proxy).
	Rotate(reason string) error
	// Name returns a short identifier for logs/metrics.
	Name() string
}

// DirectProvider is the no-op default: no proxy, no rotation. Returned
// when no proxy list / Tor is configured.
type DirectProvider struct{}

func (DirectProvider) Transport() (*http.Transport, string) { return nil, "" }
func (DirectProvider) MarkResult(string, bool)              {}
func (DirectProvider) Rotate(string) error                  { return nil }
func (DirectProvider) Name() string                         { return "direct" }

// rotatorProvider wraps the existing ProxyRotator behind the EgressProvider
// interface so callers can swap implementations without touching scanners.
type rotatorProvider struct {
	r *ProxyRotator
}

func NewRotatorProvider(r *ProxyRotator) EgressProvider {
	return &rotatorProvider{r: r}
}

func (p *rotatorProvider) Transport() (*http.Transport, string) {
	pc := p.r.Next()
	if pc == nil {
		return nil, ""
	}
	t, err := p.r.BuildTransport(pc)
	if err != nil {
		return nil, ""
	}
	return t, pc.URL
}

func (p *rotatorProvider) MarkResult(proxyID string, success bool) {
	if proxyID == "" {
		return
	}
	if success {
		p.r.MarkSuccess(proxyID)
	} else {
		p.r.MarkFailed(proxyID)
	}
}

// Rotate on a ProxyRotator is implicit — Next() round-robins over the
// available pool. For the case where the caller wants to forcibly skip
// the current proxy (e.g. it just got 429'd), we MarkFailed to bump its
// failure counter so the next Next() prefers a different entry.
func (p *rotatorProvider) Rotate(reason string) error {
	// No-op: rotation happens naturally via Next() + MarkResult.
	return nil
}

func (p *rotatorProvider) Name() string { return "rotator" }

// torProvider wraps TorDialer.
type torProvider struct {
	td *TorDialer
}

func NewTorProvider(td *TorDialer) EgressProvider {
	return &torProvider{td: td}
}

func (p *torProvider) Transport() (*http.Transport, string) {
	if p.td == nil || !p.td.IsEnabled() {
		return nil, ""
	}
	return p.td.Transport(), "tor"
}

func (p *torProvider) MarkResult(string, bool) {}

// Rotate requests a fresh Tor circuit via NEWNYM. Use sparingly — Tor
// throttles NEWNYM and circuits take a few seconds to rebuild.
func (p *torProvider) Rotate(reason string) error {
	if p.td == nil {
		return nil
	}
	return p.td.RenewIdentity()
}

func (p *torProvider) Name() string { return "tor" }
