package scanner

import (
	"context"
	"io"
	"strings"

	"github.com/temren/pkg/httpengine"
)

// MarkerIsEvaluated reports whether marker appears in body because the server
// actually evaluated the payload — rather than because it simply echoed the
// payload back.
//
// This distinction is the difference between a real injection finding and a
// reflection. Several scanners used markers that are substrings of their own
// payloads:
//
//	payload {{config.SECRET_KEY}}          marker "SECRET_KEY"
//	payload <!--#echo var="DOCUMENT_NAME"--> marker "document_name"
//
// Any endpoint that reflects input at all therefore produced a Critical
// finding at high confidence, on every parameter, without evaluating anything.
//
// Two conditions are required:
//
//  1. The marker must survive with every verbatim copy of the payload removed,
//     so a reflected payload cannot supply its own evidence.
//  2. The marker must be absent from the baseline response, so text that the
//     page always contains (a price of 49, a "root:" in documentation) does not
//     count either.
func MarkerIsEvaluated(body, payload, marker, baseline string) bool {
	if marker == "" {
		return false
	}

	lowerMarker := strings.ToLower(marker)

	// A marker the unmodified page already contains proves nothing.
	if strings.Contains(strings.ToLower(baseline), lowerMarker) {
		return false
	}

	// Remove the reflected payload before looking for the marker.
	stripped := body
	if payload != "" {
		stripped = strings.ReplaceAll(stripped, payload, "")
		// Also strip the common encodings a server may apply when echoing input.
		for _, variant := range payloadVariants(payload) {
			stripped = strings.ReplaceAll(stripped, variant, "")
		}
	}

	return strings.Contains(strings.ToLower(stripped), lowerMarker)
}

// payloadVariants returns the forms a reflected payload commonly comes back in,
// so stripping catches them too.
func payloadVariants(payload string) []string {
	htmlEscaped := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	).Replace(payload)

	return []string{
		htmlEscaped,
		strings.ToLower(payload),
		strings.ToUpper(payload),
	}
}

// fetchBaselineBody returns the unmodified response body for target, or "" if
// it cannot be fetched. Scanners use it to tell "this text is always here" from
// "the payload produced this".
func fetchBaselineBody(ctx context.Context, client *httpengine.Client, target string) string {
	resp, err := client.Get(ctx, target)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return ""
	}
	return string(body)
}
