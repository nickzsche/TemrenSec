package scanner

import "testing"

func TestMapOWASP2021To2025(t *testing.T) {
	cases := map[string]string{
		"A01:2021-Broken Access Control":                       "A01:2025-Broken Access Control",
		"A02:2021-Cryptographic Failures":                      "A04:2025-Cryptographic Failures",
		"A03:2021-Injection":                                   "A05:2025-Injection",
		"A04:2021-Insecure Design":                             "A06:2025-Insecure Design",
		"A05:2021-Security Misconfiguration":                   "A02:2025-Security Misconfiguration",
		"A05:2021 - Security Misconfiguration":                 "A02:2025-Security Misconfiguration",
		"A06:2021-Vulnerable and Outdated Components":          "A03:2025-Software Supply Chain Failures",
		"A07:2021-Identification and Authentication Failures":  "A07:2025-Authentication Failures",
		"A08:2021-Software and Data Integrity Failures":        "A08:2025-Software or Data Integrity Failures",
		"A09:2021-Security Logging and Monitoring Failures":    "A09:2025-Security Logging and Alerting Failures",
		"A10:2021-Server-Side Request Forgery":                 "A05:2025-Injection",
		"":                                                     "",
		"informational":                                        "informational",
		"some random text":                                     "some random text",
	}
	for in, want := range cases {
		if got := MapOWASP2021To2025(in); got != want {
			t.Errorf("MapOWASP2021To2025(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOWASP2025Categories_Count(t *testing.T) {
	cats := OWASP2025Categories()
	if len(cats) != 10 {
		t.Errorf("expected 10 categories, got %d", len(cats))
	}
	for _, c := range cats {
		if c == "" {
			t.Error("empty category in list")
		}
	}
}
