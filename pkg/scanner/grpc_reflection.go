package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// GRPCReflectionScanner probes whether a gRPC server has the reflection service enabled.
// We check for /grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo and
// /grpc.reflection.v1.ServerReflection over HTTP/1.1 with the gRPC content type.
type GRPCReflectionScanner struct{}

func NewGRPCReflectionScanner() *GRPCReflectionScanner { return &GRPCReflectionScanner{} }

func (s *GRPCReflectionScanner) Name() string { return "gRPC Reflection Exposed" }

func (s *GRPCReflectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	paths := []string{
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
	}
	for _, p := range paths {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(target, "/")+p, nil)
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		grpcStatus := resp.Header.Get("Grpc-Status")
		if grpcStatus == "0" || resp.StatusCode == 200 {
			return []Finding{{
				URL: target + p, Title: "gRPC Reflection Service Exposed",
				Description: "Public reflection lets attackers enumerate every RPC method and message schema, often revealing internal admin endpoints. Disable on production.",
				Severity: SeverityMedium, Confidence: ConfidenceMedium, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 5.3,
			}}, nil
		}
	}
	return nil, nil
}
