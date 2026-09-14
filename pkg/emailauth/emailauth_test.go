package emailauth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type stubResolver struct {
	txt map[string][]string
}

func (s *stubResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	if v, ok := s.txt[host]; ok {
		return v, nil
	}
	return nil, errors.New("nxdomain")
}

func TestStrictDMARCPasses(t *testing.T) {
	r := &stubResolver{txt: map[string][]string{
		"example.com":         {"v=spf1 ip4:1.2.3.4 -all"},
		"_dmarc.example.com":  {"v=DMARC1; p=quarantine; rua=mailto:reports@example.com"},
		"k1._domainkey.example.com": {"v=DKIM1; k=rsa; p=Mg…"},
	}}
	rep, err := Inspect(context.Background(), r, "example.com", []string{"k1"})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.SPFOK || !rep.DMARCOK || len(rep.DKIM) != 1 {
		t.Errorf("unexpected report: %+v", rep)
	}
}

func TestWideOpenSPFFlagged(t *testing.T) {
	r := &stubResolver{txt: map[string][]string{
		"example.com": {"v=spf1 +all"},
	}}
	rep, _ := Inspect(context.Background(), r, "example.com", nil)
	if rep.SPFOK {
		t.Error("'+all' should not be OK")
	}
	if len(rep.Issues) < 2 {
		t.Errorf("expected ≥2 issues, got %v", rep.Issues)
	}
}

func TestMissingDMARCReported(t *testing.T) {
	r := &stubResolver{txt: map[string][]string{
		"example.com": {"v=spf1 -all"},
	}}
	rep, _ := Inspect(context.Background(), r, "example.com", nil)
	var seen bool
	for _, i := range rep.Issues {
		if strings.Contains(i, "DMARC record missing") {
			seen = true
		}
	}
	if !seen {
		t.Error("expected DMARC-missing issue")
	}
}
