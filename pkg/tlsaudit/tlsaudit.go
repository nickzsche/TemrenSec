// Package tlsaudit grades a TLS endpoint's protocol, ciphers, and certificate.
// The result is a 0..100 score plus a list of issues, modeled loosely on the
// Mozilla TLS Observatory scoring.
package tlsaudit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

type Report struct {
	Host           string
	Port           string
	NegotiatedTLS  uint16
	CipherSuite    uint16
	Score          int      // 0..100
	Issues         []string
	CertSubject    string
	CertIssuer     string
	CertNotAfter   time.Time
	CertChainLen   int
	AltNames       []string
}

// Audit dials the host:port and grades the handshake.
func Audit(ctx context.Context, hostport string) (*Report, error) {
	return AuditWithConfig(ctx, hostport, nil)
}

// AuditWithConfig is like Audit but accepts a custom tls.Config (e.g. with
// InsecureSkipVerify for self-signed test servers).
func AuditWithConfig(ctx context.Context, hostport string, cfg *tls.Config) (*Report, error) {
	host, port, _ := net.SplitHostPort(hostport)
	if port == "" {
		host = hostport
		port = "443"
	}
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS10}
	}
	dialer := &tls.Dialer{Config: cfg}
	c, err := dialer.DialContext(ctx, "tcp", host+":"+port)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	tc, ok := c.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("not a TLS conn")
	}
	state := tc.ConnectionState()
	r := &Report{
		Host:          host,
		Port:          port,
		NegotiatedTLS: state.Version,
		CipherSuite:   state.CipherSuite,
		CertChainLen:  len(state.PeerCertificates),
		Score:         100,
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		r.CertSubject = leaf.Subject.String()
		r.CertIssuer = leaf.Issuer.String()
		r.CertNotAfter = leaf.NotAfter
		r.AltNames = leaf.DNSNames
		grade(leaf, r)
	}
	gradeProtocol(state.Version, r)
	gradeCipher(state.CipherSuite, r)
	if r.Score < 0 {
		r.Score = 0
	}
	return r, nil
}

func grade(c *x509.Certificate, r *Report) {
	if time.Until(c.NotAfter) < 14*24*time.Hour {
		r.Issues = append(r.Issues, "certificate expires within 14 days")
		r.Score -= 30
	}
	if !c.IsCA && time.Since(c.NotBefore) > 397*24*time.Hour {
		r.Issues = append(r.Issues, "certificate lifetime exceeds 397 days (Apple/CA-B)")
		r.Score -= 5
	}
	if c.SignatureAlgorithm == x509.SHA1WithRSA || c.SignatureAlgorithm == x509.MD5WithRSA {
		r.Issues = append(r.Issues, "certificate uses weak signature algorithm")
		r.Score -= 40
	}
}

func gradeProtocol(v uint16, r *Report) {
	switch v {
	case tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11:
		r.Issues = append(r.Issues, "deprecated TLS version "+protoName(v))
		r.Score -= 40
	case tls.VersionTLS12:
		r.Issues = append(r.Issues, "TLS 1.2 acceptable but prefer 1.3")
		r.Score -= 5
	}
}

func gradeCipher(c uint16, r *Report) {
	name := tls.CipherSuiteName(c)
	low := strings.ToLower(name)
	for _, weak := range []string{"_rc4_", "_3des_", "_des_", "_md5_", "_anon_", "_export_"} {
		if strings.Contains(low, weak) {
			r.Issues = append(r.Issues, "weak cipher "+name)
			r.Score -= 30
			return
		}
	}
	if strings.Contains(low, "_cbc_") {
		r.Issues = append(r.Issues, "CBC cipher "+name+" (BEAST/Lucky13 history)")
		r.Score -= 10
	}
}

func protoName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("%#04x", v)
}
