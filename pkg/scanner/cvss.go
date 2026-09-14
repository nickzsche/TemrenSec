// Package scanner provides CVSS v4.0 scoring and vulnerability classification
package scanner

import (
	"fmt"
	"math"
	"strings"
)

// CVSS4Vector represents a CVSS v4.0 vector string
type CVSS4Vector struct {
	AttackVector       string // N (Network), A (Adjacent), L (Local), P (Physical)
	AttackComplexity   string // L (Low), H (High)
	AttackRequirements string // N (None), R (Required)
	PrivilegesRequired string // N (None), L (Low), H (High)
	UserInteraction    string // N (None), P (Passive), A (Active)
	Scope              string // U (Unchanged), C (Changed)
	Confidentiality   string // N (None), L (Low), H (High)
	Integrity         string // N (None), L (Low), H (High)
	Availability      string // N (None), L (Low), H (High)
}

// CVSS 4.0 metric weight tables
var (
	avWeights = map[string]float64{"N": 0.97, "A": 0.62, "L": 0.55, "P": 0.20}
	acWeights = map[string]float64{"L": 0.97, "H": 0.44}
	atWeights = map[string]float64{"N": 0.97, "R": 0.62}
	prWeights = map[string]float64{"N": 0.97, "L": 0.62, "H": 0.27}
	uiWeights = map[string]float64{"N": 0.97, "P": 0.62, "A": 0.27}
	ciaWeights = map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}
)

// roundup rounds up to 1 decimal place per CVSS spec
func roundup(score float64) float64 {
	return math.Ceil(score*10) / 10
}

// CalculateCVSS4 computes the CVSS v4.0 base score from a vector
func CalculateCVSS4(vector CVSS4Vector) float64 {
	av, ok := avWeights[vector.AttackVector]
	if !ok {
		av = 0.97
	}
	ac, ok := acWeights[vector.AttackComplexity]
	if !ok {
		ac = 0.97
	}
	at, ok := atWeights[vector.AttackRequirements]
	if !ok {
		at = 0.97
	}
	pr, ok := prWeights[vector.PrivilegesRequired]
	if !ok {
		pr = 0.97
	}
	ui, ok := uiWeights[vector.UserInteraction]
	if !ok {
		ui = 0.97
	}
	c, ok := ciaWeights[vector.Confidentiality]
	if !ok {
		c = 0.0
	}
	i, ok := ciaWeights[vector.Integrity]
	if !ok {
		i = 0.0
	}
	a, ok := ciaWeights[vector.Availability]
	if !ok {
		a = 0.0
	}

	// Impact Sub Score
	iss := 1 - ((1 - c) * (1 - i) * (1 - a))

	// Impact based on scope
	var impact float64
	if vector.Scope == "C" {
		// Scope Changed
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		// Scope Unchanged (default)
		impact = 6.42 * iss
	}

	// Exploitability
	exploitability := 8.22 * av * ac * at * pr * ui

	// If impact <= 0, base score is 0
	if impact <= 0 {
		return 0.0
	}

	// Base score
	var baseScore float64
	if vector.Scope == "C" {
		baseScore = roundup(math.Min(1.08*(impact+exploitability), 10.0))
	} else {
		baseScore = roundup(math.Min(impact+exploitability, 10.0))
	}

	// Cap at 10.0
	if baseScore > 10.0 {
		baseScore = 10.0
	}

	return baseScore
}

// InferCVSS4Vector infers a CVSS v4.0 vector from a Finding's characteristics
func InferCVSS4Vector(finding Finding) CVSS4Vector {
	name := finding.Scanner

	switch name {
	case "SQL Injection":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:   "H",
			Integrity:         "H",
			Availability:      "H",
		}
	case "Cross-Site Scripting (XSS)":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "A",
			Scope:              "U",
			Confidentiality:   "N",
			Integrity:         "L",
			Availability:      "N",
		}
	case "Server-Side Request Forgery (SSRF)":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:   "H",
			Integrity:         "N",
			Availability:      "N",
		}
	case "Insecure Direct Object Reference (IDOR)":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "L",
			UserInteraction:    "N",
			Scope:              "U",
			Confidentiality:   "H",
			Integrity:         "N",
			Availability:      "N",
		}
	case "Path Traversal":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "N",
			Scope:              "U",
			Confidentiality:   "H",
			Integrity:         "N",
			Availability:      "N",
		}
	case "XML External Entity (XXE)":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:   "H",
			Integrity:         "H",
			Availability:      "N",
		}
	case "Command Injection":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:   "H",
			Integrity:         "H",
			Availability:      "H",
		}
	case "Authentication Failures":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "A",
			Scope:              "U",
			Confidentiality:   "H",
			Integrity:         "L",
			Availability:      "N",
		}
	case "CORS Misconfiguration":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "P",
			Scope:              "U",
			Confidentiality:   "L",
			Integrity:         "N",
			Availability:      "N",
		}
	case "Server-Side Template Injection (SSTI)":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:   "H",
			Integrity:         "H",
			Availability:      "H",
		}
	case "NoSQL Injection":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:   "H",
			Integrity:         "H",
			Availability:      "H",
		}
	case "Security Headers":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "P",
			Scope:              "U",
			Confidentiality:   "N",
			Integrity:         "L",
			Availability:      "N",
		}
	case "Secret Scanner":
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "N",
			Scope:              "C",
			Confidentiality:   "H",
			Integrity:         "H",
			Availability:      "H",
		}
	default:
		// Default for unknown scanners
		return CVSS4Vector{
			AttackVector:       "N",
			AttackComplexity:   "L",
			AttackRequirements: "N",
			PrivilegesRequired: "N",
			UserInteraction:    "N",
			Scope:              "U",
			Confidentiality:   "L",
			Integrity:         "L",
			Availability:      "N",
		}
	}
}

// VectorString returns the CVSS v4.0 vector string representation
func (v CVSS4Vector) VectorString() string {
	return fmt.Sprintf(
		"CVSS:4.0/AV:%s/AC:%s/AT:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		v.AttackVector,
		v.AttackComplexity,
		v.AttackRequirements,
		v.PrivilegesRequired,
		v.UserInteraction,
		v.Scope,
		v.Confidentiality,
		v.Integrity,
		v.Availability,
	)
}

// SeverityFromCVSS maps a CVSS score to a Severity level
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score >= 0.1:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// ParseCVSS4Vector parses a CVSS v4.0 vector string into a CVSS4Vector
func ParseCVSS4Vector(vectorStr string) CVSS4Vector {
	v := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "N",
		UserInteraction:    "N",
		Scope:              "U",
		Confidentiality:   "N",
		Integrity:         "N",
		Availability:      "N",
	}

	parts := strings.Split(vectorStr, "/")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		switch key {
		case "AV":
			v.AttackVector = val
		case "AC":
			v.AttackComplexity = val
		case "AT":
			v.AttackRequirements = val
		case "PR":
			v.PrivilegesRequired = val
		case "UI":
			v.UserInteraction = val
		case "S":
			v.Scope = val
		case "C":
			v.Confidentiality = val
		case "I":
			v.Integrity = val
		case "A":
			v.Availability = val
		}
	}

	return v
}