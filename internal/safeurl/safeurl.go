// Package safeurl guards outbound requests whose destination comes from user
// input, so a multi-tenant Temren deployment cannot be turned into an SSRF
// proxy into the network it is running in.
//
// Two layers, because either alone is bypassable:
//
//   - Validate() rejects an obviously unsafe destination up front, giving the
//     caller a clear error to return to the user.
//   - DialControl() re-checks the resolved address at connect time. That is
//     what actually stops DNS rebinding (a name that validates as public and
//     then resolves to 169.254.169.254 on the real dial) and redirects to a
//     private host, neither of which up-front validation can see.
package safeurl

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// AllowPrivate reports whether private/loopback destinations are permitted.
//
// Scanning an internal staging host is a legitimate use of this tool, so this
// is an opt-in escape hatch rather than a hardcoded refusal — but it must be a
// deliberate operator decision, not the default for an internet-facing install.
func AllowPrivate() bool {
	v, _ := strconv.ParseBool(os.Getenv("ALLOW_PRIVATE_TARGETS"))
	return v
}

// Validate parses raw and rejects it unless it is an http(s) URL pointing at a
// destination that is safe to reach from the server.
func Validate(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	switch u.Scheme {
	case "http", "https":
	case "":
		return fmt.Errorf("URL must start with http:// or https://")
	default:
		return fmt.Errorf("unsupported URL scheme %q (only http and https are allowed)", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}

	if AllowPrivate() {
		return nil
	}

	// A literal IP needs no lookup; a name does, and every address it resolves
	// to must be acceptable — one private answer is enough to refuse.
	if ip := net.ParseIP(host); ip != nil {
		return checkIP(ip)
	}

	if isBlockedName(host) {
		return fmt.Errorf("destination %q is not allowed", host)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%q resolved to no addresses", host)
	}
	for _, ip := range ips {
		if err := checkIP(ip); err != nil {
			return err
		}
	}
	return nil
}

// DialControl is an http.Transport DialContext control hook. Install it to
// enforce the same policy against the address actually being connected to,
// after DNS resolution and on every redirect hop.
//
//	net.Dialer{Control: safeurl.DialControl}
func DialControl(network, address string, _ syscall.RawConn) error {
	if AllowPrivate() {
		return nil
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("network %q is not allowed", network)
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("unexpected address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("unexpected address %q", address)
	}
	return checkIP(ip)
}

func checkIP(ip net.IP) error {
	// Normalise IPv4-mapped IPv6 (::ffff:169.254.169.254) to its v4 form so the
	// range checks below see the real address.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	switch {
	case ip.IsLoopback():
		return refuse(ip, "loopback")
	case ip.IsUnspecified():
		return refuse(ip, "unspecified")
	case ip.IsPrivate():
		return refuse(ip, "private")
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		// 169.254.169.254 — the cloud metadata endpoint — lives here.
		return refuse(ip, "link-local")
	case ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return refuse(ip, "multicast")
	}

	for _, r := range extraBlocked {
		if r.Contains(ip) {
			return refuse(ip, r.reason)
		}
	}
	return nil
}

func refuse(ip net.IP, class string) error {
	return fmt.Errorf("destination %s is a %s address; "+
		"set ALLOW_PRIVATE_TARGETS=true to permit internal destinations", ip, class)
}

type blockedRange struct {
	net    *net.IPNet
	reason string
}

func (b blockedRange) Contains(ip net.IP) bool { return b.net.Contains(ip) }

// Ranges that are routable-looking but still must not be reachable from a
// user-supplied destination.
var extraBlocked = mustRanges(map[string]string{
	"100.64.0.0/10":  "carrier-grade NAT",
	"192.0.0.0/24":   "IETF protocol assignment",
	"192.0.2.0/24":   "documentation",
	"198.18.0.0/15":  "benchmarking",
	"198.51.100.0/24": "documentation",
	"203.0.113.0/24": "documentation",
	"240.0.0.0/4":    "reserved",
	"::/128":         "unspecified",
	"64:ff9b::/96":   "NAT64",
	"100::/64":       "discard-only",
	"2001:db8::/32":  "documentation",
})

func mustRanges(in map[string]string) []blockedRange {
	out := make([]blockedRange, 0, len(in))
	for cidr, reason := range in {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("safeurl: bad CIDR " + cidr + ": " + err.Error())
		}
		out = append(out, blockedRange{net: n, reason: reason})
	}
	return out
}

// isBlockedName catches names that resolve to the host itself or to well-known
// metadata services, before any lookup happens.
func isBlockedName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	switch h {
	case "localhost", "metadata", "metadata.google.internal",
		"metadata.goog", "instance-data", "169.254.169.254.nip.io":
		return true
	}
	return strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".internal")
}
