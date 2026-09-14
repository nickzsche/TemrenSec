package pdf

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"

	"github.com/temren/internal/model"
	"github.com/go-pdf/fpdf"
)

// DejaVu Sans is a free Unicode TTF that covers Latin Extended-A (Turkish
// ğ ş ı İ ç ö ü Ç Ş İ Ğ etc.). The default Helvetica core font only
// supports Latin-1, which renders Turkish characters as mojibake
// ("Türkçe" → "TÃ¼rkÃ§e"). Embedding the TTF binary at build time keeps
// PDF generation self-contained — no font lookup at runtime.
//
//go:embed assets/DejaVuSans.ttf
var dejaVuSansRegular []byte

//go:embed assets/DejaVuSans-Bold.ttf
var dejaVuSansBold []byte

//go:embed assets/DejaVuSans-Oblique.ttf
var dejaVuSansOblique []byte

const reportFont = "DejaVu"

func registerFonts(doc *fpdf.Fpdf) {
	doc.AddUTF8FontFromBytes(reportFont, "", dejaVuSansRegular)
	doc.AddUTF8FontFromBytes(reportFont, "B", dejaVuSansBold)
	doc.AddUTF8FontFromBytes(reportFont, "I", dejaVuSansOblique)
}

func GenerateScanReport(scan *model.Scan, target *model.Target, vulns []*model.Vulnerability) ([]byte, error) {
	doc := fpdf.New("P", "mm", "A4", "")
	registerFonts(doc)
	doc.SetAutoPageBreak(true, 20)
	doc.AddPage()

	doc.SetFont(reportFont, "B", 24)
	doc.SetTextColor(37, 99, 235)
	doc.Cell(0, 15, "Temren Security Report")
	doc.Ln(20)

	doc.SetDrawColor(37, 99, 235)
	doc.Line(10, doc.GetY(), 200, doc.GetY())
	doc.Ln(10)

	doc.SetFont(reportFont, "", 12)
	doc.SetTextColor(0, 0, 0)

	doc.SetFont(reportFont, "B", 12)
	doc.Cell(40, 8, "Target:")
	doc.SetFont(reportFont, "", 12)
	doc.Cell(0, 8, target.URL)
	doc.Ln(8)

	doc.SetFont(reportFont, "B", 12)
	doc.Cell(40, 8, "Scan Date:")
	doc.SetFont(reportFont, "", 12)
	doc.Cell(0, 8, scan.CreatedAt.Format("2006-01-02 15:04:05"))
	doc.Ln(8)

	doc.SetFont(reportFont, "B", 12)
	doc.Cell(40, 8, "Duration:")
	doc.SetFont(reportFont, "", 12)
	doc.Cell(0, 8, fmt.Sprintf("%d seconds", scan.DurationSeconds))
	doc.Ln(8)

	doc.SetFont(reportFont, "B", 12)
	doc.Cell(40, 8, "Pages Scanned:")
	doc.SetFont(reportFont, "", 12)
	doc.Cell(0, 8, fmt.Sprintf("%d", scan.PagesCrawled))
	doc.Ln(15)

	doc.SetFont(reportFont, "B", 16)
	doc.SetTextColor(37, 99, 235)
	doc.Cell(0, 10, "Executive Summary")
	doc.Ln(12)

	drawSummaryCard(doc, "CRITICAL", scan.CriticalCount, 220, 38, 38)
	drawSummaryCard(doc, "HIGH", scan.HighCount, 249, 115, 22)
	drawSummaryCard(doc, "MEDIUM", scan.MediumCount, 234, 179, 8)
	drawSummaryCard(doc, "LOW", scan.LowCount, 37, 99, 235)
	drawSummaryCard(doc, "INFO", scan.InfoCount, 107, 114, 128)

	doc.Ln(10)
	doc.SetFont(reportFont, "B", 12)
	doc.SetTextColor(37, 99, 235)
	doc.Cell(0, 10, fmt.Sprintf("Security Score: %d/100", target.SecurityScore))
	doc.Ln(15)

	doc.SetFont(reportFont, "B", 16)
	doc.SetTextColor(37, 99, 235)
	doc.Cell(0, 10, "Vulnerability Details")
	doc.Ln(12)

	for i, v := range vulns {
		if doc.GetY() > 250 {
			doc.AddPage()
		}

		severityColor := getSeverityColor(v.Severity)
		doc.SetFillColor(severityColor[0], severityColor[1], severityColor[2])
		doc.SetTextColor(255, 255, 255)
		doc.SetFont(reportFont, "B", 10)
		doc.CellFormat(0, 8, fmt.Sprintf("  #%d [%s] %s", i+1, v.Severity, v.Title), "L", 1, "L", true, 0, "")
		doc.SetTextColor(0, 0, 0)
		doc.SetFont(reportFont, "", 9)

		if v.URL != "" {
			doc.Cell(0, 6, fmt.Sprintf("  URL: %s", truncate(v.URL, 80)))
			doc.Ln(6)
		}
		if v.OWASPCategory != "" {
			doc.Cell(0, 6, fmt.Sprintf("  OWASP: %s", v.OWASPCategory))
			doc.Ln(6)
		}
		if v.Description != "" {
			doc.MultiCell(0, 5, "  "+truncate(v.Description, 200), "", "", true)
		}
		if v.FixRecommendation != "" {
			doc.SetFont(reportFont, "I", 9)
			doc.SetTextColor(0, 128, 0)
			doc.MultiCell(0, 5, "  Fix: "+truncate(v.FixRecommendation, 200), "", "", true)
			doc.SetTextColor(0, 0, 0)
		}

		doc.Ln(5)
	}

	var buf bytes.Buffer
	err := doc.Output(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func drawSummaryCard(doc *fpdf.Fpdf, label string, count int, r, g, b int) {
	doc.SetFont(reportFont, "B", 11)
	doc.SetTextColor(r, g, b)
	doc.Cell(38, 8, fmt.Sprintf("%s: %d", label, count))
	doc.SetTextColor(0, 0, 0)
}

func getSeverityColor(severity string) [3]int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return [3]int{220, 38, 38}
	case "HIGH":
		return [3]int{249, 115, 22}
	case "MEDIUM":
		return [3]int{234, 179, 8}
	case "LOW":
		return [3]int{37, 99, 235}
	default:
		return [3]int{107, 114, 128}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
