package model

import "time"

type User struct {
	ID                string    `json:"id"`
	Email             string    `json:"email"`
	PasswordHash      string    `json:"-"`
	FullName          string    `json:"full_name"`
	Plan              string    `json:"plan"`
	TOTPSecret        string    `json:"-"`
	TOTPEnabled       bool      `json:"totp_enabled"`
	EmailVerified     bool      `json:"email_verified"`
	VerificationToken string    `json:"-"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type RefreshToken struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type Project struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Target struct {
	ID            string     `json:"id"`
	ProjectID     string     `json:"project_id"`
	URL           string     `json:"url"`
	Name          string     `json:"name"`
	ScanSettings  string     `json:"scan_settings"`
	Status        string     `json:"status"`
	LastScanAt    *time.Time `json:"last_scan_at"`
	Schedule      string     `json:"schedule"`
	SecurityScore int        `json:"security_score"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type Scan struct {
	ID              string     `json:"id"`
	TargetID        string     `json:"target_id"`
	Status          string     `json:"status"`
	StartedAt       *time.Time `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	DurationSeconds int        `json:"duration_seconds"`
	PagesCrawled    int        `json:"pages_crawled"`
	TotalFindings   int        `json:"total_findings"`
	CriticalCount   int        `json:"critical_count"`
	HighCount       int        `json:"high_count"`
	MediumCount     int        `json:"medium_count"`
	LowCount        int        `json:"low_count"`
	InfoCount       int        `json:"info_count"`
	Summary         string     `json:"summary"`
	Config          string     `json:"config"`
	Error           string     `json:"error"`
	CreatedAt       time.Time  `json:"created_at"`
}

type Vulnerability struct {
	ID                string    `json:"id"`
	ScanID            string    `json:"scan_id"`
	TargetID          string    `json:"target_id"`
	Title             string    `json:"title"`
	Severity          string    `json:"severity"`
	Description       string    `json:"description"`
	URL               string    `json:"url"`
	Parameter         string    `json:"parameter"`
	Payload           string    `json:"payload"`
	Evidence          string    `json:"evidence"`
	OWASPCategory     string    `json:"owasp_category"`
	CVSSScore         float64   `json:"cvss_score"`
	FixRecommendation string    `json:"fix_recommendation"`
	Proof             string    `json:"proof"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
}

type Report struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	UserID    string    `json:"user_id"`
	Format    string    `json:"format"`
	FilePath  string    `json:"file_path"`
	CreatedAt time.Time `json:"created_at"`
}

type ScanAlert struct {
	ID      string    `json:"id"`
	UserID  string    `json:"user_id"`
	ScanID  string    `json:"scan_id"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
	SentAt  time.Time `json:"sent_at"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	User         *User  `json:"user"`
}

type CreateProjectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type CreateTargetRequest struct {
	ProjectID    string `json:"project_id"`
	URL          string `json:"url"`
	Name         string `json:"name"`
	ScanSettings string `json:"scan_settings"`
	Schedule     string `json:"schedule"`
}

type StartScanRequest struct {
	Active      *bool `json:"active"`
	Passive     *bool `json:"passive"`
	Depth       int   `json:"depth"`
	MaxPages    int   `json:"max_pages"`
	Concurrency int   `json:"concurrency"`
	RateLimit   int   `json:"rate_limit"`
}

type DashboardStats struct {
	TotalTargets         int                 `json:"total_targets"`
	TotalScans           int                 `json:"total_scans"`
	TotalVulnerabilities int                 `json:"total_vulnerabilities"`
	CriticalCount        int                 `json:"critical_count"`
	HighCount            int                 `json:"high_count"`
	MediumCount          int                 `json:"medium_count"`
	LowCount             int                 `json:"low_count"`
	InfoCount            int                 `json:"info_count"`
	AvgSecurityScore     float64             `json:"avg_security_score"`
	RecentScans          []*Scan             `json:"recent_scans"`
	SeverityTimeline     []SeverityDataPoint `json:"severity_timeline"`
}

type SeverityDataPoint struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
}

type PlanLimits struct {
	MaxTargets int  `json:"max_targets"`
	MaxScans   int  `json:"max_scans"`
	Scheduler  bool `json:"scheduler"`
}

var PlanConfig = map[string]PlanLimits{
	"free": {MaxTargets: 1, MaxScans: 5, Scheduler: false},
	"pro":  {MaxTargets: 5, MaxScans: 50, Scheduler: true},
	"team": {MaxTargets: 20, MaxScans: 200, Scheduler: true},
}

// Workspace groups targets for org-level views (ASPM). Persisted in the
// workspaces table (migration 003).
type Workspace struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
}

// TriageSuppression persists a rule that hides matching findings across scans
// (triage_suppressions table, migration 003). Empty workspace = global.
type TriageSuppression struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspace_id,omitempty"`
	Scanner     string    `json:"scanner"`
	URLGlob     string    `json:"url_glob"`
	Param       string    `json:"param"`
	Reason      string    `json:"reason"`
	CreatedAt   time.Time `json:"created_at"`
}
