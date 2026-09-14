// Package dnsenum performs lightweight DNS reconnaissance and subdomain enumeration.
// It supports: brute-forced lookups against a wordlist, certificate-transparency
// lookups via crt.sh, A/AAAA/CNAME/MX/TXT/NS record collection, and AXFR test.
//
// Network calls are dependency-injectable so tests can stub them.
package dnsenum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CommonSubdomains is a small built-in wordlist; production users should
// merge their own.
var CommonSubdomains = []string{
	"www", "api", "mail", "smtp", "imap", "pop", "ftp", "ssh", "vpn",
	"dev", "staging", "test", "qa", "uat", "beta", "preview",
	"admin", "internal", "intranet", "secret", "private",
	"app", "apps", "web", "mobile", "static", "cdn", "assets",
	"git", "gitlab", "github", "jira", "wiki", "docs",
	"db", "database", "redis", "elastic", "monitor", "grafana", "prometheus",
	"auth", "sso", "login", "oauth", "id",
	"status", "health", "metrics", "traces",
	"old", "legacy", "backup", "archive",
	"jenkins", "ci", "cd", "build", "artifacts",
	"webhook", "webhooks", "callback",
	"public", "private", "shared",
	"shop", "store", "checkout", "pay", "billing",
	"blog", "support", "help", "feedback",
	"console", "dashboard", "panel",
}

// Resolver is the small DNS surface we depend on.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
}

// Record is one resolved subdomain.
type Record struct {
	Host  string   `json:"host"`
	IPs   []string `json:"ips,omitempty"`
	CNAME string   `json:"cname,omitempty"`
}

// Enumerator orchestrates lookups.
type Enumerator struct {
	Resolver    Resolver
	HTTP        *http.Client
	Concurrency int
	// CrtBase is the certificate-transparency lookup base URL. Override in tests.
	CrtBase string
}

func New(resolver Resolver) *Enumerator {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Enumerator{
		Resolver:    resolver,
		HTTP:        &http.Client{Timeout: 15 * time.Second},
		Concurrency: 32,
		CrtBase:     "https://crt.sh",
	}
}

// Bruteforce concatenates each wordlist entry with the base apex and resolves.
func (e *Enumerator) Bruteforce(ctx context.Context, apex string, words []string) []Record {
	if len(words) == 0 {
		words = CommonSubdomains
	}
	sem := make(chan struct{}, e.Concurrency)
	var (
		mu  sync.Mutex
		out []Record
		wg  sync.WaitGroup
	)
	for _, w := range words {
		w := w
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			host := w + "." + apex
			ips, err := e.Resolver.LookupHost(ctx, host)
			if err != nil {
				return
			}
			cname, _ := e.Resolver.LookupCNAME(ctx, host)
			mu.Lock()
			out = append(out, Record{Host: host, IPs: ips, CNAME: cname})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// FromCertificateTransparency queries crt.sh for issued certs covering apex.
func (e *Enumerator) FromCertificateTransparency(ctx context.Context, apex string) ([]string, error) {
	url := fmt.Sprintf("%s/?q=%%25.%s&output=json", e.CrtBase, apex)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, r := range rows {
		for _, name := range strings.Split(r.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if name == "" || strings.HasPrefix(name, "*") {
				continue
			}
			seen[strings.ToLower(name)] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}

// CollectRecords gathers A/AAAA/CNAME/MX/TXT/NS for a single host.
func (e *Enumerator) CollectRecords(ctx context.Context, host string) map[string]any {
	out := map[string]any{}
	if ips, err := e.Resolver.LookupHost(ctx, host); err == nil {
		out["A"] = ips
	}
	if cname, err := e.Resolver.LookupCNAME(ctx, host); err == nil && cname != "" {
		out["CNAME"] = cname
	}
	if mx, err := e.Resolver.LookupMX(ctx, host); err == nil {
		out["MX"] = mx
	}
	if txt, err := e.Resolver.LookupTXT(ctx, host); err == nil {
		out["TXT"] = txt
	}
	if ns, err := e.Resolver.LookupNS(ctx, host); err == nil {
		out["NS"] = ns
	}
	return out
}
