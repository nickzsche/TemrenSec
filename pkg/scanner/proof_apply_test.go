package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/temren/pkg/httpengine"
)

func TestApplyVerification_ConfirmsErrorBasedSQLi(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("id"), "'\"") {
			_, _ = w.Write([]byte("You have an error in your SQL syntax"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	pv := NewProofVerifier(httpengine.NewClient(httpengine.DefaultConfig()))
	in := []Finding{{
		URL:        srv.URL + "/?id=1",
		Title:      "SQL Injection (error-based)",
		Severity:   SeverityCritical,
		Confidence: ConfidenceMedium,
		Scanner:    "SQL Injection",
	}}
	out := pv.ApplyVerification(context.Background(), in)
	if len(out) != 1 || !out[0].Verified {
		t.Fatalf("expected verified error-based SQLi, got %+v", out)
	}
	if out[0].Confidence != ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", out[0].Confidence)
	}
}

func TestApplyVerification_DowngradesUnprovable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nothing interesting, no delay, no error"))
	}))
	defer srv.Close()

	pv := NewProofVerifier(httpengine.NewClient(httpengine.DefaultConfig()))
	in := []Finding{{
		URL:        srv.URL + "/?id=1",
		Title:      "SQL Injection (time-based blind)",
		Severity:   SeverityCritical,
		Confidence: ConfidenceMedium,
		Scanner:    "SQL Injection",
	}}
	out := pv.ApplyVerification(context.Background(), in)
	if out[0].Verified {
		t.Fatalf("expected unproved finding to stay unverified, got %+v", out[0])
	}
	if out[0].Confidence != ConfidenceLow {
		t.Errorf("expected confidence downgraded to LOW, got %s", out[0].Confidence)
	}
}

func TestApplyVerification_LeavesMediumUntouched(t *testing.T) {
	pv := NewProofVerifier(httpengine.NewClient(httpengine.DefaultConfig()))
	in := []Finding{{
		URL:        "http://127.0.0.1:1/?x=1",
		Title:      "Missing Security Header",
		Severity:   SeverityMedium,
		Confidence: ConfidenceMedium,
	}}
	out := pv.ApplyVerification(context.Background(), in)
	if out[0].Verified || out[0].Confidence != ConfidenceMedium {
		t.Fatalf("medium finding should be untouched, got %+v", out[0])
	}
}

func TestApplyVerification_UnknownTypeKeepsConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	pv := NewProofVerifier(httpengine.NewClient(httpengine.DefaultConfig()))
	in := []Finding{{
		URL:        srv.URL + "/?x=1",
		Title:      "Exposed Secret: AWS Access Key",
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Scanner:    "Secret Scanner",
	}}
	out := pv.ApplyVerification(context.Background(), in)
	// No proof strategy for secrets -> confidence preserved, not downgraded.
	if out[0].Confidence != ConfidenceHigh {
		t.Fatalf("secret finding confidence should be preserved, got %+v", out[0])
	}
}

func TestEngineDefaultVerifyOn(t *testing.T) {
	e := NewScanEngine(httpengine.NewClient(httpengine.DefaultConfig()), nil, 2)
	if !e.verify {
		t.Fatal("engine should verify by default")
	}
	e.SetVerify(false)
	if e.verify {
		t.Fatal("SetVerify(false) should disable verification")
	}
	_ = time.Second
}
