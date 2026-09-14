package scanner

import (
	"fmt"
	"strings"
)

type DiffCategory string

const (
	DiffFixed      DiffCategory = "FIXED"
	DiffNew        DiffCategory = "NEW"
	DiffRegressed  DiffCategory = "REGRESSED"
	DiffUnchanged  DiffCategory = "UNCHANGED"
)

type DiffEntry struct {
	Finding  Finding     `json:"finding"`
	Category DiffCategory `json:"category"`
	Previous *Finding    `json:"previous,omitempty"`
}

type DiffResult struct {
	Fixed      []DiffEntry `json:"fixed"`
	New        []DiffEntry `json:"new"`
	Regressed  []DiffEntry `json:"regressed"`
	Unchanged  []DiffEntry `json:"unchanged"`
	Summary    DiffSummary `json:"summary"`
}

type DiffSummary struct {
	TotalPrevious int `json:"total_previous"`
	TotalCurrent  int `json:"total_current"`
	Fixed         int `json:"fixed"`
	New           int `json:"new"`
	Regressed     int `json:"regressed"`
	Unchanged     int `json:"unchanged"`
}

func CompareScans(previous, current []Finding) DiffResult {
	result := DiffResult{
		Fixed:     []DiffEntry{},
		New:       []DiffEntry{},
		Regressed: []DiffEntry{},
		Unchanged: []DiffEntry{},
	}

	prevMap := buildFindingMap(previous)
	currMap := buildFindingMap(current)

	for key, prevFinding := range prevMap {
		if currFinding, exists := currMap[key]; exists {
			if isRegression(prevFinding, currFinding) {
				result.Regressed = append(result.Regressed, DiffEntry{
					Finding:  currFinding,
					Category: DiffRegressed,
					Previous: &prevFinding,
				})
			} else {
				result.Unchanged = append(result.Unchanged, DiffEntry{
					Finding:  currFinding,
					Category: DiffUnchanged,
					Previous: &prevFinding,
				})
			}
		} else {
			result.Fixed = append(result.Fixed, DiffEntry{
				Finding:  prevFinding,
				Category: DiffFixed,
			})
		}
	}

	for key, currFinding := range currMap {
		if _, exists := prevMap[key]; !exists {
			result.New = append(result.New, DiffEntry{
				Finding:  currFinding,
				Category: DiffNew,
			})
		}
	}

	result.Summary = DiffSummary{
		TotalPrevious: len(previous),
		TotalCurrent:  len(current),
		Fixed:         len(result.Fixed),
		New:           len(result.New),
		Regressed:     len(result.Regressed),
		Unchanged:     len(result.Unchanged),
	}

	return result
}

func (d DiffResult) String() string {
	var sb strings.Builder

	sb.WriteString("=========================================\n")
	sb.WriteString(" Temren Differential Scan Report\n")
	sb.WriteString("=========================================\n\n")

	sb.WriteString(fmt.Sprintf("Previous: %d findings | Current: %d findings\n\n", d.Summary.TotalPrevious, d.Summary.TotalCurrent))
	sb.WriteString(fmt.Sprintf("  FIXED:       %d\n", d.Summary.Fixed))
	sb.WriteString(fmt.Sprintf("  NEW:         %d\n", d.Summary.New))
	sb.WriteString(fmt.Sprintf("  REGRESSED:   %d\n", d.Summary.Regressed))
	sb.WriteString(fmt.Sprintf("  UNCHANGED:   %d\n\n", d.Summary.Unchanged))

	printSection := func(title string, entries []DiffEntry) {
		if len(entries) == 0 {
			return
		}
		sb.WriteString(fmt.Sprintf("--- %s (%d) ---\n", title, len(entries)))
		for i, e := range entries {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, e.Finding.Severity, e.Finding.Title))
			sb.WriteString(fmt.Sprintf("   URL: %s", e.Finding.URL))
			if e.Finding.Parameter != "" {
				sb.WriteString(fmt.Sprintf(" | Param: %s", e.Finding.Parameter))
			}
			sb.WriteString("\n")
			if e.Previous != nil && e.Category == DiffRegressed {
				sb.WriteString(fmt.Sprintf("   Previous: [%s] -> Current: [%s]\n", e.Previous.Severity, e.Finding.Severity))
			}
		}
		sb.WriteString("\n")
	}

	printSection("FIXED", d.Fixed)
	printSection("NEW", d.New)
	printSection("REGRESSED", d.Regressed)
	printSection("UNCHANGED", d.Unchanged)

	return sb.String()
}

func findingKey(f Finding) string {
	return fmt.Sprintf("%s|%s|%s", f.URL, f.Title, f.Parameter)
}

func buildFindingMap(findings []Finding) map[string]Finding {
	m := make(map[string]Finding, len(findings))
	for _, f := range findings {
		m[findingKey(f)] = f
	}
	return m
}

func isRegression(prev, curr Finding) bool {
	return severityRank(curr.Severity) > severityRank(prev.Severity)
}

func severityRank(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
