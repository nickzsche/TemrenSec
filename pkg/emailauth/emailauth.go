// Package emailauth inspects SPF / DKIM / DMARC records for a given domain.
// All resolutions go through a pluggable Resolver so tests can stub them.
package emailauth

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type Resolver interface {
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

type Report struct {
	Domain    string
	SPF       string
	SPFOK     bool
	DKIM      []string
	DMARC     string
	DMARCOK   bool
	Issues    []string
}

func Inspect(ctx context.Context, r Resolver, domain string, dkimSelectors []string) (*Report, error) {
	if r == nil {
		r = net.DefaultResolver
	}
	out := &Report{Domain: domain}

	if txts, err := r.LookupTXT(ctx, domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				out.SPF = t
				out.SPFOK = !strings.Contains(t, "+all")
				if strings.Contains(t, "+all") {
					out.Issues = append(out.Issues, "SPF '+all' permits any sender — wide-open")
				}
				break
			}
		}
	}
	if out.SPF == "" {
		out.Issues = append(out.Issues, "SPF record missing")
	}

	if txts, err := r.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, t := range txts {
			low := strings.ToLower(t)
			if strings.HasPrefix(low, "v=dmarc1") {
				out.DMARC = t
				if strings.Contains(low, "p=none") {
					out.Issues = append(out.Issues, "DMARC policy = none (monitor only)")
				} else {
					out.DMARCOK = true
				}
				if !strings.Contains(low, "rua=") {
					out.Issues = append(out.Issues, "DMARC missing rua= reporting address")
				}
				break
			}
		}
	}
	if out.DMARC == "" {
		out.Issues = append(out.Issues, "DMARC record missing")
	}

	for _, sel := range dkimSelectors {
		host := fmt.Sprintf("%s._domainkey.%s", sel, domain)
		if txts, err := r.LookupTXT(ctx, host); err == nil {
			for _, t := range txts {
				if strings.Contains(strings.ToLower(t), "v=dkim1") {
					out.DKIM = append(out.DKIM, sel+": "+t)
					break
				}
			}
		}
	}
	if len(out.DKIM) == 0 && len(dkimSelectors) > 0 {
		out.Issues = append(out.Issues, "no DKIM records for provided selectors")
	}
	return out, nil
}
