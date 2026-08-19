package safeurl

import (
	"net"
	"strings"
	"testing"
)

func TestValidateRejectsMetadataAndInternalAddresses(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "")

	blocked := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://[fd00::1]/",
		"http://127.0.0.1:6379/",
		"http://127.1/",
		"https://localhost/admin",
		"http://10.0.0.5/internal",
		"http://172.16.4.1/",
		"http://192.168.1.1/",
		"http://0.0.0.0/",
		"http://[::1]:8080/",
		"http://[::ffff:169.254.169.254]/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://100.64.0.1/",
		"http://198.18.0.1/",
	}

	for _, raw := range blocked {
		if err := Validate(raw); err == nil {
			t.Errorf("Validate(%q) = nil, expected the destination to be refused", raw)
		}
	}
}

func TestValidateRejectsNonHTTPSchemes(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "")

	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://127.0.0.1:6379/_SET%20k%20v",
		"redis://127.0.0.1:6379",
		"ftp://example.com/",
		"example.com/no-scheme",
	} {
		if err := Validate(raw); err == nil {
			t.Errorf("Validate(%q) = nil, expected the scheme to be refused", raw)
		}
	}
}

func TestValidateAcceptsPublicHTTPURLs(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "")

	// A literal public address needs no DNS, keeping this test hermetic.
	for _, raw := range []string{
		"http://93.184.216.34/",
		"https://93.184.216.34:8443/scan?a=1",
		"https://[2606:2800:220:1:248:1893:25c8:1946]/",
	} {
		if err := Validate(raw); err != nil {
			t.Errorf("Validate(%q) = %v, expected it to be allowed", raw, err)
		}
	}
}

func TestAllowPrivateOptsOutOfTheCheck(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "true")

	// Operators scanning their own internal apps must still be able to.
	for _, raw := range []string{
		"http://127.0.0.1:3000/",
		"http://10.1.2.3/",
		"http://169.254.169.254/",
	} {
		if err := Validate(raw); err != nil {
			t.Errorf("Validate(%q) with ALLOW_PRIVATE_TARGETS=true = %v, want nil", raw, err)
		}
	}
}

func TestDialControlBlocksPrivateAddressesAtConnectTime(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "")

	// This is the layer that catches DNS rebinding: the name may have validated
	// as public, but the address actually dialled is what matters.
	for _, addr := range []string{
		"169.254.169.254:80",
		"127.0.0.1:6379",
		"10.0.0.1:8080",
		"[::1]:443",
	} {
		if err := DialControl("tcp", addr, nil); err == nil {
			t.Errorf("DialControl(tcp, %q) = nil, expected the dial to be refused", addr)
		}
	}

	if err := DialControl("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("DialControl on a public address = %v, want nil", err)
	}
}

func TestDialControlRejectsNonTCPNetworks(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "")

	if err := DialControl("udp", "93.184.216.34:53", nil); err == nil {
		t.Error("DialControl allowed a udp dial")
	}
}

func TestDialControlHonoursOptOut(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "1")

	if err := DialControl("tcp", "127.0.0.1:3000", nil); err != nil {
		t.Errorf("DialControl with opt-out = %v, want nil", err)
	}
}

// TestRefusalMentionsTheOptOut — an operator scanning their own staging box
// needs the error to tell them how to permit it.
func TestRefusalMentionsTheOptOut(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "")

	err := Validate("http://10.0.0.1/")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "ALLOW_PRIVATE_TARGETS") {
		t.Errorf("refusal %q does not mention the opt-out", err)
	}
}

func TestCheckIPCoversEveryClassWeClaimToBlock(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "")

	cases := map[string]string{
		"loopback":   "127.0.0.1",
		"private-10": "10.255.255.254",
		"private-72": "172.31.255.254",
		"private-92": "192.168.255.254",
		"link-local": "169.254.1.1",
		"v6-private": "fd12:3456::1",
		"v6-linklok": "fe80::1",
		"multicast":  "224.0.0.1",
		"reserved":   "240.0.0.1",
	}
	for name, addr := range cases {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("%s: test address %q does not parse", name, addr)
		}
		if err := checkIP(ip); err == nil {
			t.Errorf("%s (%s) was allowed", name, addr)
		}
	}
}
