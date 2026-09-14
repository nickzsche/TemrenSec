package dnsenum

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubResolver struct {
	hosts map[string][]string
	cname map[string]string
}

func (s *stubResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if v, ok := s.hosts[host]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "nxdomain"}
}
func (s *stubResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if v, ok := s.cname[host]; ok {
		return v, nil
	}
	return host + ".", nil
}
func (s *stubResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) { return nil, nil }
func (s *stubResolver) LookupTXT(ctx context.Context, host string) ([]string, error) { return nil, nil }
func (s *stubResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) { return nil, nil }

func TestBruteforceReturnsResolvedHosts(t *testing.T) {
	r := &stubResolver{
		hosts: map[string][]string{
			"api.example.com": {"1.2.3.4"},
			"www.example.com": {"5.6.7.8"},
		},
	}
	e := New(r)
	e.Concurrency = 8
	out := e.Bruteforce(context.Background(), "example.com", []string{"api", "www", "ghost"})
	if len(out) != 2 {
		t.Fatalf("expected 2 resolved, got %d", len(out))
	}
}

func TestFromCertificateTransparencyParsesRows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
            {"name_value":"a.example.com\nb.example.com"},
            {"name_value":"*.example.com"}
        ]`))
	}))
	defer srv.Close()
	e := New(&stubResolver{})
	e.CrtBase = srv.URL
	names, err := e.FromCertificateTransparency(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d (%v)", len(names), names)
	}
	for _, n := range names {
		if strings.HasPrefix(n, "*") {
			t.Errorf("wildcard should be filtered: %s", n)
		}
	}
}
