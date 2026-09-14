package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestSSRFCloudMetadata_SkipsStaticAssets(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewSSRFCloudMetadataScanner()
	_, _ = s.Scan(context.Background(), srv.URL+"/_next/static/chunks/abc.js", httpengine.NewClient(httpengine.DefaultConfig()))
	if hits != 0 {
		t.Errorf("scanner sent %d requests to a static asset URL — should skip", hits)
	}
}

func TestSSRFCloudMetadata_RejectsSPAHTMLResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// HTML body that happens to contain "instance-id" and "compute project"
		// in prose — old check would match these.
		_, _ = w.Write([]byte(`<html><body>Edit instance-id, compute project quotas in dashboard</body></html>`))
	}))
	defer srv.Close()

	s := NewSSRFCloudMetadataScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/api/proxy", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Errorf("SPA HTML produced %d FP findings: %+v", len(findings), findings)
	}
}

func TestSSRFCloudMetadata_RealAWSMetadataIsFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only fire on the AWS metadata-target probe to keep the test deterministic.
		w.Header().Set("Content-Type", "text/plain")
		// Real AWS metadata listing
		_, _ = w.Write([]byte("ami-id\nami-launch-index\ninstance-id\niam/\nplacement/"))
	}))
	defer srv.Close()

	s := NewSSRFCloudMetadataScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/api/proxy", httpengine.NewClient(httpengine.DefaultConfig()))
	hit := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Cloud Metadata Reachable") {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("real AWS metadata exfil was missed: %+v", findings)
	}
}

func TestSSRFCloudMetadata_RealAWSCredsJSONIsFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Code":"Success","AccessKeyId":"ASIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Token":"..."}`))
	}))
	defer srv.Close()

	s := NewSSRFCloudMetadataScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/api/proxy", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) == 0 {
		t.Fatalf("AWS creds JSON was missed: %+v", findings)
	}
}
