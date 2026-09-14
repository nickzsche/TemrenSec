package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestCloudLeak_OrdinaryHTMLProducesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Contains words like AWS, KEY, PASSWORD in prose — old scanner fired on all of these.
		_, _ = w.Write([]byte(`<html><body>
            <p>We use AWS for our infrastructure. Choose a strong PASSWORD and store the API KEY safely.</p>
            <button class="bucket=list-action">Bucket List</button>
        </body></html>`))
	}))
	defer srv.Close()

	s := NewCloudLeakScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Errorf("ordinary HTML produced %d cloud-leak findings: %+v", len(findings), findings)
	}
}

func TestCloudLeak_RealS3BucketURLIsFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><img src="https://my-prod-assets.s3.amazonaws.com/logo.png"></body></html>`))
	}))
	defer srv.Close()

	s := NewCloudLeakScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	hit := false
	for _, f := range findings {
		if strings.Contains(f.Title, "S3 bucket") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("real S3 bucket URL was missed: %+v", findings)
	}
}

func TestCloudLeak_RealAzureBlobIsFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><script src="https://acmeprod.blob.core.windows.net/assets/app.js"></script></body></html>`))
	}))
	defer srv.Close()

	s := NewCloudLeakScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	hit := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Azure") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("real Azure Blob URL was missed: %+v", findings)
	}
}

func TestCloudLeak_DedupsRepeatedReferences(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same bucket URL referenced four times — should produce one finding.
		_, _ = w.Write([]byte(`<html><body>
            <img src="https://acme.s3.amazonaws.com/a.png">
            <img src="https://acme.s3.amazonaws.com/a.png">
            <img src="https://acme.s3.amazonaws.com/a.png">
            <img src="https://acme.s3.amazonaws.com/a.png">
        </body></html>`))
	}))
	defer srv.Close()

	s := NewCloudLeakScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 1 {
		t.Errorf("expected 1 deduped finding, got %d: %+v", len(findings), findings)
	}
}

func TestCloudLeak_PerHostCache(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`<html><body>nothing</body></html>`))
	}))
	defer srv.Close()

	s := NewCloudLeakScanner()
	c := httpengine.NewClient(httpengine.DefaultConfig())
	_, _ = s.Scan(context.Background(), srv.URL+"/a", c)
	first := hits
	_, _ = s.Scan(context.Background(), srv.URL+"/b", c)
	_, _ = s.Scan(context.Background(), srv.URL+"/c", c)
	if hits != first {
		t.Errorf("per-host cache not engaged: %d extra requests", hits-first)
	}
}
