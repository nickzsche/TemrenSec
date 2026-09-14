// Package docs Temren OWASP Security Scanner API
//
// Documentation for Temren OWASP Security Scanner API
//
//	Schemes: https
//	BasePath: /api/v1
//	Version: 1.0.0
//	Host: api.temren.sh
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
//	Security:
//	- bearer
//
//	SecurityDefinitions:
//	bearer:
//	     type: apiKey
//	     name: Authorization
//	     in: header
//
// swagger:meta
package docs

import "github.com/temren/internal/model"

// swagger:route GET /health health check
// Returns the health status of the API.
// responses:
//   200: healthResponse

// swagger:response healthResponse
//nolint:unused
type healthResponse struct {
	// in:body
	Body struct {
		Status    string `json:"status"`
		Service   string `json:"service"`
		Timestamp string `json:"timestamp"`
	}
}

// swagger:route POST /auth/register auth register
// Register a new user account.
// responses:
//   201: authResponse
//   400: errorResponse

// swagger:route POST /auth/login auth login
// Login with email and password.
// responses:
//   200: authResponse
//   401: errorResponse

// swagger:response authResponse
//nolint:unused
type authResponse struct {
	// in:body
	Body struct {
		AccessToken  string       `json:"access_token"`
		RefreshToken string       `json:"refresh_token"`
		User         *model.User  `json:"user"`
	}
}

// swagger:response errorResponse
//nolint:unused
type errorResponse struct {
	// in:body
	Body struct {
		Error string `json:"error"`
	}
}

// swagger:route GET /dashboard dashboard getDashboard
// Get dashboard statistics.
// responses:
//   200: dashboardResponse
//   401: errorResponse

// swagger:response dashboardResponse
//nolint:unused
type dashboardResponse struct {
	// in:body
	Body *model.DashboardStats
}

// swagger:route POST /projects projects createProject
// Create a new project.
// responses:
//   201: projectResponse
//   400: errorResponse

// swagger:route GET /projects projects listProjects
// List all projects for the authenticated user.
// responses:
//   200: projectsResponse

// swagger:response projectResponse
//nolint:unused
type projectResponse struct {
	// in:body
	Body *model.Project
}

// swagger:response projectsResponse
//nolint:unused
type projectsResponse struct {
	// in:body
	Body struct {
		Projects []*model.Project `json:"projects"`
	}
}

// swagger:route POST /targets targets createTarget
// Create a new target URL to scan.
// responses:
//   201: targetResponse
//   400: errorResponse

// swagger:response targetResponse
//nolint:unused
type targetResponse struct {
	// in:body
	Body *model.Target
}

// swagger:route POST /targets/{targetId}/scans scans startScan
// Start a new scan for a target.
// responses:
//   201: scanResponse
//   400: errorResponse

// swagger:route GET /scans/{scanId} scans getScan
// Get scan details and status.
// responses:
//   200: scanDetailResponse
//   404: errorResponse

// swagger:response scanResponse
//nolint:unused
type scanResponse struct {
	// in:body
	Body *model.Scan
}

// swagger:response scanDetailResponse
//nolint:unused
type scanDetailResponse struct {
	// in:body
	Body *model.Scan
}

// swagger:route GET /scans/{scanId}/vulnerabilities scans getVulnerabilities
// Get vulnerabilities found by a scan.
// responses:
//   200: vulnerabilitiesResponse

// swagger:response vulnerabilitiesResponse
//nolint:unused
type vulnerabilitiesResponse struct {
	// in:body
	Body struct {
		Vulnerabilities []*model.Vulnerability `json:"vulnerabilities"`
	}
}

// swagger:route POST /cli/scan-results cli receiveScanResults
// Receive scan results from CLI tool.
// responses:
//   200: cliScanResponse

// swagger:response cliScanResponse
//nolint:unused
type cliScanResponse struct {
	// in:body
	Body struct {
		Message   string `json:"message"`
		ReportID  string `json:"report_id"`
		ReportURL string `json:"report_url"`
	}
}
