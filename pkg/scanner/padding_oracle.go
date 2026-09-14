package scanner

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// PaddingOracleScanner probes cookies/tokens whose decoded length is a multiple of 8/16
// and whose ciphertext flip produces a distinguishable "padding error" vs "MAC error" response.
type PaddingOracleScanner struct{}

func NewPaddingOracleScanner() *PaddingOracleScanner { return &PaddingOracleScanner{} }

func (s *PaddingOracleScanner) Name() string { return "Padding Oracle Probe" }

func (s *PaddingOracleScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	cookies := resp.Cookies()
	resp.Body.Close()
	var findings []Finding
	for _, c := range cookies {
		raw, err := base64.URLEncoding.DecodeString(strings.ReplaceAll(c.Value, "%3D", "="))
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(c.Value)
		}
		if err != nil || (len(raw)%8 != 0 && len(raw)%16 != 0) || len(raw) < 16 {
			continue
		}
		flipped := flipLastByte(raw)
		newCookie := base64.URLEncoding.EncodeToString(flipped)

		reqGood, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		reqGood.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		good := snapshot(ctx, client, reqGood)

		reqBad, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		reqBad.AddCookie(&http.Cookie{Name: c.Name, Value: newCookie})
		bad := snapshot(ctx, client, reqBad)

		if good.status != bad.status || (good.length > 0 && abs(good.length-bad.length) > 10) {
			findings = append(findings, Finding{
				URL: target, Title: "Possible Padding Oracle: cookie " + c.Name,
				Description: "Cookie body length aligns with AES-CBC blocks; flipping the last ciphertext byte changed the response. Investigate with PadBuster / poracle.",
				Severity: SeverityHigh, Confidence: ConfidenceLow, Scanner: s.Name(),
				Evidence: "good=" + itoa(good.status) + "/" + itoa(good.length) +
					" bad=" + itoa(bad.status) + "/" + itoa(bad.length),
				Timestamp: time.Now(),
				OWASPCategory: "A02:2021-Cryptographic Failures", CVSSScore: 7.5,
			})
		}
	}
	return findings, nil
}

func flipLastByte(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[len(out)-1] ^= 0xFF
	return out
}

type snap struct {
	status int
	length int
}

func snapshot(ctx context.Context, client *httpengine.Client, req *http.Request) snap {
	resp, err := client.Do(ctx, req)
	if err != nil {
		return snap{}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	resp.Body.Close()
	return snap{status: resp.StatusCode, length: len(body)}
}
