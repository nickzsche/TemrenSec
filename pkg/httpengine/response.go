package httpengine

import (
	"io"
	"net/http"
	"strings"
)

// Response wraps http.Response with additional metadata
type Response struct {
	*http.Response
	Body       []byte
	URL        string
	StatusCode int
	Headers    http.Header
	Latency    int64 // milliseconds
}

// ReadBody reads and caches the response body
func (r *Response) ReadBody() ([]byte, error) {
	if r.Body != nil {
		return r.Body, nil
	}

	body, err := io.ReadAll(r.Response.Body)
	if err != nil {
		return nil, err
	}
	r.Body = body
	return body, nil
}

// GetHeader returns a header value (case-insensitive)
func (r *Response) GetHeader(key string) string {
	return r.Headers.Get(key)
}

// HasHeader checks if a header exists
func (r *Response) HasHeader(key string) bool {
	_, ok := r.Headers[http.CanonicalHeaderKey(key)]
	return ok
}

// ContentType returns the Content-Type header
func (r *Response) ContentType() string {
	ct := r.GetHeader("Content-Type")
	if idx := strings.Index(ct, ";"); idx != -1 {
		return ct[:idx]
	}
	return ct
}

// IsHTML checks if response is HTML
func (r *Response) IsHTML() bool {
	return strings.Contains(r.ContentType(), "text/html")
}

// IsJSON checks if response is JSON
func (r *Response) IsJSON() bool {
	ct := r.ContentType()
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "text/json")
}
