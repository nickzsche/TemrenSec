package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestFileUpload_NoopWithoutURL(t *testing.T) {
	// Default registry construction passes "" — must not run against the target.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"name":"static manifest"}`))
	}))
	defer srv.Close()
	f, _ := NewFileUploadBypassScanner("").Scan(context.Background(), srv.URL+"/manifest.webmanifest", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) != 0 {
		t.Fatalf("no-URL scanner must be a no-op, got %+v", f)
	}
}

func TestFileUpload_NoFPOnStatic200(t *testing.T) {
	// Explicit URL, but endpoint just echoes static content (ignores upload).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"name":"Sigortapedia","short_name":"Sigortapedia"}`))
	}))
	defer srv.Close()
	f, _ := NewFileUploadBypassScanner(srv.URL+"/manifest.webmanifest").Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) != 0 {
		t.Fatalf("static 200 without upload evidence must not be flagged, got %+v", f)
	}
}

func TestFileUpload_DetectsRealAcceptance(t *testing.T) {
	// A real upload endpoint echoes the stored filename / success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseMultipartForm(1 << 20)
		fn := "unknown"
		if r.MultipartForm != nil && len(r.MultipartForm.File["file"]) > 0 {
			fn = r.MultipartForm.File["file"][0].Filename
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"success":true,"url":"/uploads/` + fn + `"}`))
	}))
	defer srv.Close()
	f, _ := NewFileUploadBypassScanner(srv.URL+"/upload").Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) == 0 {
		t.Fatal("genuine upload acceptance (filename echoed) must be detected")
	}
}
