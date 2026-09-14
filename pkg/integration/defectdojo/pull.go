package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FindingUpdate is the unidirectional projection of a DefectDojo finding
// back onto an Temren vulnerability. We deliberately keep this small —
// Temren treats DefectDojo as authoritative for *status* (triage decision)
// and *notes*, but never re-writes severity/title/description in either
// direction. That keeps a one-way merge: Temren pushes findings, DD pushes
// triage state.
type FindingUpdate struct {
	DDFindingID   int       `json:"dd_finding_id"`
	TemrenVulnID   string    `json:"temren_vuln_id"` // extracted from DD tags
	Status        string    `json:"status"`        // active | false_positive | risk_accepted | verified
	Severity      string    `json:"severity"`
	Notes         string    `json:"notes,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ddFinding is the subset of /api/v2/findings/ we consume.
type ddFinding struct {
	ID               int       `json:"id"`
	Title            string    `json:"title"`
	Severity         string    `json:"severity"`
	Active           bool      `json:"active"`
	Verified         bool      `json:"verified"`
	FalseP           bool      `json:"false_p"`
	RiskAccepted     bool      `json:"risk_accepted"`
	Tags             []string  `json:"tags"`
	NotesURL         string    `json:"notes"`
	LastStatusUpdate time.Time `json:"last_status_update"`
	Mitigated        time.Time `json:"mitigated"`
}

type ddFindingPage struct {
	Count    int         `json:"count"`
	Next     string      `json:"next"`
	Results  []ddFinding `json:"results"`
}

// PullFindings fetches DefectDojo findings whose last_status_update is at
// or after `since`. Use it from a scheduler to sync triage state back to
// Temren, e.g. every 5 minutes.
//
// Pagination is followed automatically. Callers should treat the returned
// slice as a batch: deduplicate by DDFindingID and reconcile against the
// Temren DB.
func (c *Client) PullFindings(ctx context.Context, since time.Time) ([]FindingUpdate, error) {
	base := strings.TrimRight(c.config.BaseURL, "/")

	q := url.Values{}
	q.Set("last_status_update__gte", since.UTC().Format(time.RFC3339))
	q.Set("limit", "100")
	endpoint := base + "/api/v2/findings/?" + q.Encode()

	var out []FindingUpdate
	for endpoint != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Token "+c.config.APIToken)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("get findings: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("defectdojo /findings returned %d: %s", resp.StatusCode, string(body))
		}

		var page ddFindingPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode page: %w", err)
		}
		for _, f := range page.Results {
			out = append(out, projectFinding(f))
		}
		endpoint = page.Next
	}
	return out, nil
}

// projectFinding turns a DefectDojo finding into our small FindingUpdate.
// Status precedence: false_p > risk_accepted > verified > active.
func projectFinding(f ddFinding) FindingUpdate {
	status := "active"
	switch {
	case f.FalseP:
		status = "false_positive"
	case f.RiskAccepted:
		status = "risk_accepted"
	case !f.Active && !f.Mitigated.IsZero():
		status = "mitigated"
	case f.Verified:
		status = "verified"
	}
	return FindingUpdate{
		DDFindingID:   f.ID,
		TemrenVulnID:   extractTemrenID(f.Tags),
		Status:        status,
		Severity:      f.Severity,
		UpdatedAt:     f.LastStatusUpdate,
	}
}

// extractTemrenID pulls the "temren-id:<uuid>" tag the push side embeds when
// it creates a finding in DefectDojo. Returns empty string if not present
// — caller decides whether to skip orphan updates or attempt fuzzy match.
func extractTemrenID(tags []string) string {
	const prefix = "temren-id:"
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			return strings.TrimPrefix(t, prefix)
		}
	}
	return ""
}
