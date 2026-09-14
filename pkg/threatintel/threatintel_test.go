package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func stubServer(responses map[string]string) *httptest.Server {
	mux := http.NewServeMux()
	for path, body := range responses {
		path, body := path, body
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(body))
		})
	}
	return httptest.NewServer(mux)
}

func TestLookupReturnsZeroOnBadID(t *testing.T) {
	c := New()
	info, err := c.Lookup(context.Background(), "not-a-cve")
	if err != nil || info.ID != "" {
		t.Errorf("expected zero info on bad ID, got %+v / %v", info, err)
	}
}

func TestLookupNVDIntegration(t *testing.T) {
	srv := stubServer(map[string]string{
		"/nvd": `{"vulnerabilities":[{"cve":{"id":"CVE-2024-9999","descriptions":[{"lang":"en","value":"Test"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5}}]},"references":[{"url":"https://example.com"}]}}]}`,
		"/epss": `{"data":[{"epss":"0.85","percentile":"0.99"}]}`,
		"/kev":  `{"vulnerabilities":[{"cveID":"CVE-2024-9999","dateAdded":"2024-05-01"}]}`,
	})
	defer srv.Close()

	c := New()
	c.NVDBase = srv.URL + "/nvd"
	c.EPSSBase = srv.URL + "/epss"
	c.KEVURL = srv.URL + "/kev"

	info, err := c.Lookup(context.Background(), "cve-2024-9999")
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "CVE-2024-9999" || info.CVSS != 7.5 {
		t.Errorf("unexpected info: %+v", info)
	}
	if info.EPSS < 0.8 || !info.KEV {
		t.Errorf("expected EPSS≥0.8 and KEV=true, got %+v", info)
	}
	if !strings.HasPrefix(info.Description, "Test") {
		t.Errorf("description not set: %q", info.Description)
	}

	// Second call should be served from cache (no panic on closed server)
	info2, _ := c.Lookup(context.Background(), "CVE-2024-9999")
	if info2.CVSS != info.CVSS {
		t.Errorf("cache miss")
	}
}

func TestPrioritizationKEVFloor(t *testing.T) {
	got := PrioritizationScore(CVEInfo{CVSS: 4.0, EPSS: 0.05, KEV: true})
	if got < 9.0 {
		t.Errorf("KEV should floor score at 9.0, got %v", got)
	}
}

func TestPrioritizationBlend(t *testing.T) {
	got := PrioritizationScore(CVEInfo{CVSS: 10, EPSS: 1.0})
	if got != 10 {
		t.Errorf("max should be 10, got %v", got)
	}
}
