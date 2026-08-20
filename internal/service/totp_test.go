package service

import (
	"net/url"
	"strings"
	"testing"
)

// rfc6238Secret is the shared secret from RFC 6238 Appendix B ("12345678901234567890"),
// base32-encoded as an authenticator app would receive it.
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestGenerateTOTPCodeMatchesRFC6238 pins the algorithm to the official SHA-1
// vectors. The implementation previously used HMAC-SHA256 while handing out an
// otpauth URI that declared no algorithm — so authenticator apps computed SHA-1
// codes that could never match, and 2FA was unusable. These vectors fail if
// anyone swaps the hash again.
func TestGenerateTOTPCodeMatchesRFC6238(t *testing.T) {
	cases := []struct {
		unixTime int64
		want     string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}

	for _, tc := range cases {
		step := tc.unixTime / totpPeriod
		if got := generateTOTPCode(rfc6238Secret, step); got != tc.want {
			t.Errorf("generateTOTPCode(t=%d, step=%d) = %q, want %q", tc.unixTime, step, got, tc.want)
		}
	}
}

func TestGenerateTOTPCodeIsSixDigits(t *testing.T) {
	for step := int64(0); step < 200; step++ {
		code := generateTOTPCode(rfc6238Secret, step)
		if len(code) != totpDigits {
			t.Fatalf("step %d produced %q (%d chars), want %d digits", step, code, len(code), totpDigits)
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("step %d produced non-digit code %q", step, code)
			}
		}
	}
}

func TestGenerateTOTPCodeRejectsBadSecret(t *testing.T) {
	if got := generateTOTPCode("not-valid-base32!!!", 1); got != "" {
		t.Errorf("expected empty code for undecodable secret, got %q", got)
	}
}

func TestValidateTOTPRejectsWrongLengthAndValue(t *testing.T) {
	if ValidateTOTP(rfc6238Secret, "") {
		t.Error("empty code accepted")
	}
	if ValidateTOTP(rfc6238Secret, "12345") {
		t.Error("5-digit code accepted")
	}
	if ValidateTOTP(rfc6238Secret, "0000000") {
		t.Error("7-digit code accepted")
	}
	if ValidateTOTP(rfc6238Secret, "999999") && ValidateTOTP(rfc6238Secret, "000000") {
		t.Error("two different codes both validated; comparison is not checking the value")
	}
}

// TestTOTPURIDeclaresItsParameters guards the other half of the bug: even with
// the right hash, an app only agrees if the URI states what it is enrolling.
func TestTOTPURIDeclaresItsParameters(t *testing.T) {
	uri := TOTPURI("user@example.com", rfc6238Secret)

	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("unexpected URI scheme: %q", uri)
	}

	q, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("URI does not parse: %v", err)
	}
	params := q.Query()

	for key, want := range map[string]string{
		"algorithm": "SHA1",
		"digits":    "6",
		"period":    "30",
		"secret":    rfc6238Secret,
		"issuer":    "Temren",
	} {
		if got := params.Get(key); got != want {
			t.Errorf("otpauth URI %s = %q, want %q", key, got, want)
		}
	}
}

// TestTOTPURIEscapesLabel — an unescaped address with a '/' or '#' would
// truncate the label and produce a URI the app cannot read.
func TestTOTPURIEscapesLabel(t *testing.T) {
	uri := TOTPURI("odd/name#1@example.com", rfc6238Secret)
	label := strings.TrimPrefix(strings.SplitN(uri, "?", 2)[0], "otpauth://totp/")

	if strings.ContainsAny(label, "/#") {
		t.Errorf("label not escaped: %q", label)
	}
	decoded, err := url.PathUnescape(label)
	if err != nil {
		t.Fatalf("label does not unescape: %v", err)
	}
	if decoded != "Temren:odd/name#1@example.com" {
		t.Errorf("decoded label = %q", decoded)
	}
}
