// Package wordlists ships a few small, curated wordlists for path / parameter / subdomain
// enumeration. They are intentionally short — production users should layer their own
// or pull SecLists at build time.
package wordlists

import _ "embed"

import "strings"

//go:embed data/paths.txt
var pathsData string

//go:embed data/params.txt
var paramsData string

//go:embed data/subdomains.txt
var subdomainsData string

// Paths returns the embedded path wordlist (deduped, sorted).
func Paths() []string { return split(pathsData) }

// Params returns the embedded parameter-name wordlist.
func Params() []string { return split(paramsData) }

// Subdomains returns the embedded subdomain wordlist.
func Subdomains() []string { return split(subdomainsData) }

func split(s string) []string {
	out := make([]string, 0, 256)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
