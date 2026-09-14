package risk

import (
	"testing"

	"github.com/temren/pkg/scanner"
)

func TestKEVFloor(t *testing.T) {
	got := Score(
		scanner.Finding{Severity: scanner.SeverityMedium, CVSSScore: 5},
		Intel{KEV: true},
		AssetContext{Tier: Tier2, Exposure: ExposureInternal},
	)
	if got < 75 {
		t.Errorf("KEV should boost meaningfully; got %v", got)
	}
}

func TestInternetExposureRaisesScore(t *testing.T) {
	finding := scanner.Finding{Severity: scanner.SeverityHigh, CVSSScore: 7.5}
	internet := Score(finding, Intel{}, AssetContext{Exposure: ExposureInternet, Tier: Tier2})
	internal := Score(finding, Intel{}, AssetContext{Exposure: ExposureInternal, Tier: Tier2})
	if internet <= internal {
		t.Errorf("internet=%v should exceed internal=%v", internet, internal)
	}
}

func TestWAFLowersScore(t *testing.T) {
	finding := scanner.Finding{Severity: scanner.SeverityHigh, CVSSScore: 7.5}
	with := Score(finding, Intel{}, AssetContext{Exposure: ExposureInternet, Tier: Tier1, HasWAF: true})
	without := Score(finding, Intel{}, AssetContext{Exposure: ExposureInternet, Tier: Tier1, HasWAF: false})
	if with >= without {
		t.Errorf("WAF should lower score: with=%v without=%v", with, without)
	}
}

func TestBand(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{95, "Critical"}, {75, "High"}, {45, "Medium"}, {25, "Low"}, {5, "Informational"},
	}
	for _, c := range cases {
		if got := Band(c.score); got != c.want {
			t.Errorf("Band(%v) = %q; want %q", c.score, got, c.want)
		}
	}
}
