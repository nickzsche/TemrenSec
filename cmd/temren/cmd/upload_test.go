package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/temren/pkg/scanner"
)

func TestUploadScanResults(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cli/scan-results" || r.Header.Get("Authorization") != "Bearer tsk_x" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"scan_id":"s1","total_findings":1}`))
	}))
	defer srv.Close()

	findings := []scanner.Finding{{Title: "SQLi", Severity: scanner.SeverityHigh, URL: "http://t/?id=1"}}
	res, err := uploadScanResults(context.Background(), srv.URL+"/", "tsk_x", "tgt", findings, 3, 5*time.Second)
	if err != nil || res.ScanID != "s1" {
		t.Fatalf("upload: %+v %v", res, err)
	}
	if got["target_id"] != "tgt" || got["duration_sec"].(float64) != 5 {
		t.Fatalf("payload: %+v", got)
	}
	row := got["findings"].([]interface{})[0].(map[string]interface{})
	if row["severity"] != "HIGH" || row["title"] != "SQLi" {
		t.Fatalf("finding row: %+v", row)
	}

	if _, err := uploadScanResults(context.Background(), srv.URL, "tsk_bad", "tgt", nil, 0, 0); err == nil {
		t.Fatal("expected error on 401")
	}
}
