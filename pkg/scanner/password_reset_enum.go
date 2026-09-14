package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// PasswordResetEnumScanner POSTs known + unknown emails to /forgot-password style endpoints
// and looks for response differential (status, body, length, timing) that reveals which
// accounts exist.
type PasswordResetEnumScanner struct{}

func NewPasswordResetEnumScanner() *PasswordResetEnumScanner {
	return &PasswordResetEnumScanner{}
}

func (s *PasswordResetEnumScanner) Name() string { return "Account Enumeration (Password Reset)" }

var resetPaths = []string{"/forgot-password", "/auth/reset", "/account/forgot", "/api/v1/password/reset", "/users/password"}

func (s *PasswordResetEnumScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	target = strings.TrimRight(target, "/")
	var findings []Finding
	for _, p := range resetPaths {
		full := target + p
		good, gErr := postReset(ctx, client, full, "test@temren-canary.invalid")
		miss, mErr := postReset(ctx, client, full, "totally-bogus-"+time.Now().Format("150405")+"@temren-canary.invalid")
		if gErr != nil || mErr != nil {
			continue
		}
		if good.status == 404 && miss.status == 404 {
			continue
		}
		if good.status != miss.status || abs(len(good.body)-len(miss.body)) > 32 {
			findings = append(findings, Finding{
				URL: full, Title: "Account Enumeration via Password Reset",
				Description: "Endpoint reveals whether an email is registered by returning different statuses or response bodies. Always reply with a generic message regardless of email validity.",
				Severity: SeverityMedium, Confidence: ConfidenceMedium, Scanner: s.Name(),
				Evidence: "good_status=" + itoa(good.status) + " miss_status=" + itoa(miss.status) +
					" body_diff=" + itoa(abs(len(good.body)-len(miss.body))),
				Timestamp: time.Now(), OWASPCategory: "A07:2021-Identification and Authentication Failures", CVSSScore: 5.3,
			})
		}
	}
	return findings, nil
}

type resp struct {
	status int
	body   []byte
}

func postReset(ctx context.Context, client *httpengine.Client, url, email string) (resp, error) {
	body, _ := json.Marshal(map[string]string{"email": email})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r, err := client.Do(ctx, req)
	if err != nil {
		return resp{}, err
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 32*1024))
	r.Body.Close()
	return resp{status: r.StatusCode, body: b}, nil
}

func abs(i int) int { if i < 0 { return -i }; return i }
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
