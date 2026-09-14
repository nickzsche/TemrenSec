// Package threatintel enriches findings with CVE data: NVD CVSS, EPSS (Exploit Prediction
// Scoring System), and CISA KEV (Known Exploited Vulnerabilities) flags.
//
// All three sources are queried lazily and cached in-memory. Network calls are isolated
// behind small interfaces so they can be stubbed in tests.
package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CVEInfo is the enriched view returned to callers.
type CVEInfo struct {
	ID           string    `json:"id"`
	Description  string    `json:"description"`
	CVSS         float64   `json:"cvss_v3"`
	EPSS         float64   `json:"epss"`         // 0..1 probability of exploitation in next 30 days
	EPSSPctile   float64   `json:"epss_percentile"`
	KEV          bool      `json:"kev"`          // CISA Known-Exploited
	KEVDateAdded time.Time `json:"kev_date,omitempty"`
	References   []string  `json:"references"`
}

// Doer is the minimum http.Client surface we need. Inject a stub in tests.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is safe for concurrent use.
type Client struct {
	HTTP    Doer
	NVDBase string
	EPSSBase string
	KEVURL  string

	mu    sync.RWMutex
	cache map[string]CVEInfo
	kev   map[string]time.Time
	kevOnce sync.Once
}

// New returns a client pointed at public endpoints.
func New() *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 15 * time.Second},
		NVDBase:  "https://services.nvd.nist.gov/rest/json/cves/2.0",
		EPSSBase: "https://api.first.org/data/v1/epss",
		KEVURL:   "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		cache:    make(map[string]CVEInfo),
		kev:      make(map[string]time.Time),
	}
}

// Lookup enriches a CVE ID. Empty / malformed IDs return (zero, nil) without a network call.
func (c *Client) Lookup(ctx context.Context, cveID string) (CVEInfo, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		return CVEInfo{}, nil
	}
	c.mu.RLock()
	if v, ok := c.cache[cveID]; ok {
		c.mu.RUnlock()
		return v, nil
	}
	c.mu.RUnlock()

	info := CVEInfo{ID: cveID}

	// NVD
	if c.NVDBase != "" {
		url := fmt.Sprintf("%s?cveId=%s", c.NVDBase, cveID)
		if v, err := c.fetchNVD(ctx, url); err == nil {
			info.Description = v.Description
			info.CVSS = v.CVSS
			info.References = v.References
		}
	}

	// EPSS
	if c.EPSSBase != "" {
		url := fmt.Sprintf("%s?cve=%s", c.EPSSBase, cveID)
		if v, err := c.fetchEPSS(ctx, url); err == nil {
			info.EPSS = v.epss
			info.EPSSPctile = v.percentile
		}
	}

	// KEV
	if err := c.ensureKEV(ctx); err == nil {
		c.mu.RLock()
		if t, ok := c.kev[cveID]; ok {
			info.KEV = true
			info.KEVDateAdded = t
		}
		c.mu.RUnlock()
	}

	c.mu.Lock()
	c.cache[cveID] = info
	c.mu.Unlock()
	return info, nil
}

func (c *Client) fetchNVD(ctx context.Context, url string) (CVEInfo, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return CVEInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return CVEInfo{}, fmt.Errorf("nvd %d", resp.StatusCode)
	}
	var raw struct {
		Vulnerabilities []struct {
			Cve struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return CVEInfo{}, err
	}
	if len(raw.Vulnerabilities) == 0 {
		return CVEInfo{}, fmt.Errorf("not found")
	}
	v := raw.Vulnerabilities[0].Cve
	out := CVEInfo{ID: v.ID}
	for _, d := range v.Descriptions {
		if d.Lang == "en" {
			out.Description = d.Value
			break
		}
	}
	if len(v.Metrics.CvssMetricV31) > 0 {
		out.CVSS = v.Metrics.CvssMetricV31[0].CvssData.BaseScore
	}
	for _, r := range v.References {
		out.References = append(out.References, r.URL)
	}
	return out, nil
}

type epssRow struct {
	epss       float64
	percentile float64
}

func (c *Client) fetchEPSS(ctx context.Context, url string) (epssRow, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return epssRow{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return epssRow{}, fmt.Errorf("epss %d", resp.StatusCode)
	}
	var raw struct {
		Data []struct {
			Epss       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return epssRow{}, err
	}
	if len(raw.Data) == 0 {
		return epssRow{}, fmt.Errorf("not found")
	}
	var out epssRow
	fmt.Sscanf(raw.Data[0].Epss, "%f", &out.epss)
	fmt.Sscanf(raw.Data[0].Percentile, "%f", &out.percentile)
	return out, nil
}

func (c *Client) ensureKEV(ctx context.Context) error {
	var loadErr error
	c.kevOnce.Do(func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.KEVURL, nil)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			loadErr = err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			loadErr = fmt.Errorf("kev %d", resp.StatusCode)
			return
		}
		var raw struct {
			Vulnerabilities []struct {
				CveID     string `json:"cveID"`
				DateAdded string `json:"dateAdded"`
			} `json:"vulnerabilities"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			loadErr = err
			return
		}
		c.mu.Lock()
		for _, v := range raw.Vulnerabilities {
			t, _ := time.Parse("2006-01-02", v.DateAdded)
			c.kev[strings.ToUpper(v.CveID)] = t
		}
		c.mu.Unlock()
	})
	return loadErr
}

// PrioritizationScore combines CVSS, EPSS and KEV into a single 0..10 risk score
// suitable for executive prioritization. KEV boosts to at least 9.0; CVSS contributes 70%, EPSS 30%.
func PrioritizationScore(info CVEInfo) float64 {
	score := info.CVSS*0.7 + info.EPSS*10*0.3
	if info.KEV && score < 9.0 {
		score = 9.0
	}
	if score > 10 {
		score = 10
	}
	return score
}
