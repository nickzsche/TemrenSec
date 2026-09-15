package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestSAML_NoFPOnReflected404(t *testing.T) {
	// 404 page that reflects the requested path (so it contains "saml").
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<html><body>Sayfa bulunamadi: " + r.URL.Path + "</body></html>"))
	}))
	defer srv.Close()
	f, _ := NewSAMLEndpointScanner().Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) != 0 {
		t.Fatalf("reflected-path 404 must not be flagged as SAML endpoint, got %+v", f)
	}
}

func TestSAML_DetectsRealEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/saml/acs" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService/></samlp:Response>`))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()
	f, _ := NewSAMLEndpointScanner().Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) == 0 {
		t.Fatal("genuine SAML ACS with markers must be detected")
	}
}
