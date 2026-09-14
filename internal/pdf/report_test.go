package pdf

import (
	"bytes"
	"compress/zlib"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/temren/internal/model"
)

// TestGeneratePDF_TurkishCharacters verifies that DejaVu UTF-8 embedding
// renders Turkish characters intact instead of the Latin-1 mojibake the
// core Helvetica font produced ("Türkçe" → "TÃ¼rkÃ§e").
//
// We decompress the PDF's content stream and look for the Unicode CIDs of
// the Turkish-specific glyphs. Helvetica would emit raw UTF-8 bytes that
// the PDF viewer would decode as Latin-1; the UTF-8 font path emits
// glyph-indexed strings, so the *literal* byte sequences won't appear —
// instead we assert mojibake is absent.
func TestGeneratePDF_TurkishCharacters(t *testing.T) {
	now := time.Now()
	scan := &model.Scan{
		ID: "s1", DurationSeconds: 12, PagesCrawled: 5,
		CriticalCount: 1, HighCount: 2, CreatedAt: now,
	}
	target := &model.Target{ID: "t1", URL: "https://türkçe-test.example", SecurityScore: 78}
	vulns := []*model.Vulnerability{
		{
			Title:       "Türkçe başlık: İçerik güvenliği",
			Severity:    "HIGH",
			Description: "Güvenlik açığı bulundu — ğüşıöç İĞŞÖÇÜ.",
			URL:         "https://example.test/şehir/güvenlik",
			OWASPCategory: "A05:2025-Injection",
		},
	}

	out, err := GenerateScanReport(scan, target, vulns)
	if err != nil {
		t.Fatalf("GenerateScanReport: %v", err)
	}
	if len(out) < 1000 {
		t.Fatalf("PDF too small (%d bytes), font embed likely failed", len(out))
	}

	// Mojibake check: decompress every FlateDecode stream and confirm the
	// classic Latin-1-decoded-as-UTF-8 byte sequences don't appear.
	streams := extractFlateStreams(t, out)
	if len(streams) == 0 {
		t.Fatal("no compressed streams found in PDF")
	}
	mojibakeMarkers := []string{
		"TÃ¼rk",   // "Türk"
		"Ã§e",     // "çe"
		"gÃ¼ven", // "güven"
	}
	for _, s := range streams {
		for _, marker := range mojibakeMarkers {
			if bytes.Contains(s, []byte(marker)) {
				t.Errorf("PDF stream contains mojibake marker %q — UTF-8 font not active", marker)
			}
		}
	}
}

func TestGeneratePDF_BasicShape(t *testing.T) {
	scan := &model.Scan{CreatedAt: time.Now()}
	target := &model.Target{URL: "https://example.com"}
	out, err := GenerateScanReport(scan, target, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("not a PDF (missing %PDF- header)")
	}
}

// extractFlateStreams walks the PDF, finds `stream ... endstream` blocks,
// and zlib-decompresses each. Returns decompressed payloads. Stream content
// can be binary, so we use bytes throughout.
func extractFlateStreams(t *testing.T, pdf []byte) [][]byte {
	t.Helper()
	var out [][]byte
	rest := pdf
	for {
		i := bytes.Index(rest, []byte("stream"))
		if i < 0 {
			return out
		}
		// Skip "stream" + EOL (\n or \r\n)
		start := i + len("stream")
		for start < len(rest) && (rest[start] == '\r' || rest[start] == '\n') {
			start++
		}
		end := bytes.Index(rest[start:], []byte("endstream"))
		if end < 0 {
			return out
		}
		raw := rest[start : start+end]
		if dec, ok := tryFlate(raw); ok {
			out = append(out, dec)
		}
		rest = rest[start+end+len("endstream"):]
		// Sanity bound — stop after first 50 streams in case of weird PDFs.
		if len(out) > 50 {
			return out
		}
	}
}

func tryFlate(raw []byte) ([]byte, bool) {
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	dec, err := io.ReadAll(zr)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return nil, false
	}
	return dec, true
}
