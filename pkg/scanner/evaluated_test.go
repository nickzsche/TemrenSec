package scanner

import "testing"

// TestMarkerIsEvaluatedRejectsSelfMatchingPayloads is the core regression guard.
//
// Several scanners used a marker that is a substring of their own payload, so
// any endpoint that reflected input produced a Critical finding at high
// confidence without evaluating anything. These are the exact payload/marker
// pairs that were shipping.
func TestMarkerIsEvaluatedRejectsSelfMatchingPayloads(t *testing.T) {
	cases := []struct {
		name     string
		payload  string
		marker   string
		body     string
		baseline string
	}{
		{
			name:     "Jinja2 config probe reflected verbatim",
			payload:  "{{config.SECRET_KEY}}",
			marker:   "SECRET_KEY",
			body:     "<html><body>Hello {{config.SECRET_KEY}}</body></html>",
			baseline: "<html><body>Hello ada</body></html>",
		},
		{
			name:     "SSI echo directive reflected verbatim",
			payload:  `<!--#echo var="DOCUMENT_NAME" -->`,
			marker:   "document_name",
			body:     `<html><body>Hello <!--#echo var="DOCUMENT_NAME" --></body></html>`,
			baseline: "<html><body>Hello ada</body></html>",
		},
		{
			name:     "reflected but HTML-escaped",
			payload:  "{{config.SECRET_KEY}}",
			marker:   "SECRET_KEY",
			body:     "<html><body>Hello &lt;{{config.SECRET_KEY}}&gt;</body></html>",
			baseline: "<html><body>Hello ada</body></html>",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if MarkerIsEvaluated(tc.body, tc.payload, tc.marker, tc.baseline) {
				t.Errorf("reflection alone was treated as evaluation")
			}
		})
	}
}

// TestMarkerIsEvaluatedRejectsMarkersAlreadyOnThePage — "49" from {{7*7}} is
// meaningless if the page always contained it.
func TestMarkerIsEvaluatedRejectsMarkersAlreadyOnThePage(t *testing.T) {
	baseline := `<html><body><span class="price">49</span></body></html>`
	body := `<html><body><span class="price">49</span> {{7*7}}</body></html>`

	if MarkerIsEvaluated(body, "{{7*7}}", "49", baseline) {
		t.Error("a marker present in the baseline was treated as evidence")
	}
}

// TestMarkerIsEvaluatedAcceptsRealEvaluation — when the engine actually renders
// the expression, the marker appears and the payload does not.
func TestMarkerIsEvaluatedAcceptsRealEvaluation(t *testing.T) {
	baseline := "<html><body>Hello ada</body></html>"

	cases := []struct{ name, payload, marker, body string }{
		{
			name:    "7*7 rendered to 49",
			payload: "{{7*7}}",
			marker:  "49",
			body:    "<html><body>Hello 49</body></html>",
		},
		{
			name:    "id command executed",
			payload: "${T(java.lang.Runtime).getRuntime().exec('id')}",
			marker:  "uid=",
			body:    "<html><body>uid=0(root) gid=0(root)</body></html>",
		},
		{
			name:    "SSI resolved the document name",
			payload: `<!--#echo var="DOCUMENT_NAME" -->`,
			marker:  "profile",
			body:    "<html><body>Hello profile</body></html>",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !MarkerIsEvaluated(tc.body, tc.payload, tc.marker, baseline) {
				t.Errorf("real evaluation was not detected")
			}
		})
	}
}

func TestMarkerIsEvaluatedHandlesEmptyInput(t *testing.T) {
	if MarkerIsEvaluated("body", "payload", "", "") {
		t.Error("empty marker matched")
	}
	// No baseline available: the payload-attribution rule must still apply.
	if MarkerIsEvaluated("Hello {{config.SECRET_KEY}}", "{{config.SECRET_KEY}}", "SECRET_KEY", "") {
		t.Error("reflection matched when no baseline was available")
	}
}

// TestSSTIDetectionNeedsBaselineDifference pins the scanner-level behaviour:
// "49" anywhere on the page used to be enough for a Critical finding.
func TestSSTIDetectionNeedsBaselineDifference(t *testing.T) {
	s := NewSSTIScanner()

	alwaysHas49 := `<html><body>Order #4900 total 49 USD</body></html>`
	if s.detectSSTI(alwaysHas49+" {{7*7}}", "{{7*7}}", alwaysHas49) {
		t.Error("a page that always contains 49 was reported as SSTI")
	}

	if s.detectSSTI("<html><body>result 49</body></html>", "{{7*7}}", "<html><body>result</body></html>") {
		// This one SHOULD detect — assert the positive direction explicitly.
	} else {
		t.Error("a genuinely evaluated 7*7 was not detected")
	}

	// A bare 500 page is not proof of template injection.
	if s.detectSSTI("<html><body>Internal Server Error</body></html>", "{{7*7}}", "<html><body>ok</body></html>") {
		t.Error("a generic 500 page was reported as SSTI")
	}
}
