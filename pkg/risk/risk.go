// Package risk produces a blended risk score that combines:
//
//   - CVSS                  technical severity (0..10)
//   - EPSS                  empirical exploit probability (0..1)
//   - KEV                   known-exploited (boolean → big multiplier)
//   - Asset exposure        internet vs internal vs offline
//   - Asset criticality     business tier (tier1 critical → tier3 dev)
//   - Compensating controls e.g., WAF in front → mild discount
//
// The function is deterministic and side-effect-free so tests can pin expected
// outputs. Output is 0..100 to map cleanly to UI heatmaps.
package risk

import "github.com/temren/pkg/scanner"

type Exposure string

const (
	ExposureInternet Exposure = "internet"
	ExposureInternal Exposure = "internal"
	ExposureOffline  Exposure = "offline"
)

type Tier string

const (
	Tier1 Tier = "tier1" // crown jewels
	Tier2 Tier = "tier2" // important
	Tier3 Tier = "tier3" // experimental / dev
)

type AssetContext struct {
	Exposure          Exposure
	Tier              Tier
	HasWAF            bool
	HasMFA            bool
	HasNetworkPolicy  bool
}

type Intel struct {
	CVSS float64
	EPSS float64
	KEV  bool
}

// Score returns a 0..100 risk number for one finding.
func Score(f scanner.Finding, intel Intel, ctx AssetContext) float64 {
	base := f.CVSSScore
	if intel.CVSS > base {
		base = intel.CVSS
	}
	if base == 0 {
		base = baseFromSeverity(f.Severity)
	}

	// 0..100
	score := base * 10

	// Exploitability multiplier from EPSS — 0% adds 0%, 100% adds +20%.
	score *= 1 + intel.EPSS*0.2

	// KEV adds a fixed bump and a floor.
	if intel.KEV {
		score += 15
		if score < 90 {
			score = 90
		}
	}

	// Exposure multiplier.
	switch ctx.Exposure {
	case ExposureInternet:
		score *= 1.15
	case ExposureInternal:
		score *= 0.9
	case ExposureOffline:
		score *= 0.6
	}

	// Tier multiplier.
	switch ctx.Tier {
	case Tier1:
		score *= 1.2
	case Tier2:
		score *= 1.0
	case Tier3:
		score *= 0.7
	}

	// Compensating controls.
	if ctx.HasWAF {
		score *= 0.9
	}
	if ctx.HasMFA && (f.OWASPCategory == "A07:2021-Identification and Authentication Failures" ||
		f.OWASPCategory == "A01:2021-Broken Access Control") {
		score *= 0.85
	}
	if ctx.HasNetworkPolicy && f.OWASPCategory == "A10:2021-SSRF" {
		score *= 0.8
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

func baseFromSeverity(s scanner.Severity) float64 {
	switch s {
	case scanner.SeverityCritical:
		return 9.5
	case scanner.SeverityHigh:
		return 7.5
	case scanner.SeverityMedium:
		return 5.0
	case scanner.SeverityLow:
		return 3.0
	default:
		return 1.0
	}
}

// Band maps a score to a human label (green/yellow/orange/red/critical).
func Band(score float64) string {
	switch {
	case score >= 90:
		return "Critical"
	case score >= 70:
		return "High"
	case score >= 40:
		return "Medium"
	case score >= 20:
		return "Low"
	default:
		return "Informational"
	}
}
