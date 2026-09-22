package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/temren/internal/database"
	"github.com/temren/internal/model"
)

type ScanService struct {
	scanDB    *database.ScanRepo
	targetDB  *database.TargetRepo
	projectDB *database.ProjectRepo
	vulnDB    *database.VulnerabilityRepo
	userDB    *database.UserRepo
}

func NewScanService() *ScanService {
	return &ScanService{
		scanDB:    database.NewScanRepo(),
		targetDB:  database.NewTargetRepo(),
		projectDB: database.NewProjectRepo(),
		vulnDB:    database.NewVulnerabilityRepo(),
		userDB:    database.NewUserRepo(),
	}
}

func (s *ScanService) getUserPlan(ctx context.Context, userID string) string {
	user, err := s.userDB.GetByID(ctx, userID)
	if err != nil {
		return "free"
	}
	return user.Plan
}

func (s *ScanService) StartScan(ctx context.Context, userID, targetID string, req *model.StartScanRequest) (*model.Scan, error) {
	target, err := s.targetDB.GetByID(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("target not found")
	}

	p, err := s.projectDB.GetByID(ctx, target.ProjectID)
	if err != nil {
		return nil, err
	}
	if p.UserID != userID {
		return nil, ErrForbidden
	}

	scanCount, err := s.scanDB.CountByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	limits := model.PlanConfig[s.getUserPlan(ctx, userID)]
	if scanCount >= limits.MaxScans {
		return nil, ErrPlanLimit
	}

	depth := 2
	maxPages := 50
	concurrency := 5
	rateLimit := 10
	active := true
	passive := true

	if req != nil {
		if req.Depth > 0 {
			depth = req.Depth
		}
		if req.MaxPages > 0 {
			maxPages = req.MaxPages
		}
		if req.Concurrency > 0 {
			concurrency = req.Concurrency
		}
		if req.RateLimit > 0 {
			rateLimit = req.RateLimit
		}
		if req.Active != nil {
			active = *req.Active
		}
		if req.Passive != nil {
			passive = *req.Passive
		}
	}

	configMap := map[string]interface{}{
		"depth":       depth,
		"max_pages":   maxPages,
		"concurrency": concurrency,
		"rate_limit":  rateLimit,
		"active":      active,
		"passive":     passive,
	}
	configJSON, _ := json.Marshal(configMap)

	scan := &model.Scan{
		TargetID: targetID,
		Status:   "pending",
		Config:   string(configJSON),
	}

	if err := s.scanDB.Create(ctx, scan); err != nil {
		return nil, err
	}

	return scan, nil
}

func (s *ScanService) GetScan(ctx context.Context, scanID, userID string) (*model.Scan, error) {
	scan, err := s.scanDB.GetByID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("scan not found")
	}

	if err := s.checkScanOwnership(ctx, scan, userID); err != nil {
		return nil, err
	}

	return scan, nil
}

func (s *ScanService) ListScans(ctx context.Context, targetID, userID string, limit, offset int) ([]*model.Scan, error) {
	target, err := s.targetDB.GetByID(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("target not found")
	}

	p, err := s.projectDB.GetByID(ctx, target.ProjectID)
	if err != nil {
		return nil, err
	}
	if p.UserID != userID {
		return nil, ErrForbidden
	}

	return s.scanDB.ListByTarget(ctx, targetID, limit, offset)
}

func (s *ScanService) GetVulnerabilities(ctx context.Context, scanID, userID, severity string, limit, offset int) ([]*model.Vulnerability, error) {
	scan, err := s.scanDB.GetByID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("scan not found")
	}

	if err := s.checkScanOwnership(ctx, scan, userID); err != nil {
		return nil, err
	}

	return s.vulnDB.ListByScan(ctx, scanID, severity, limit, offset)
}

func (s *ScanService) GetVulnerability(ctx context.Context, vulnID, userID string) (*model.Vulnerability, error) {
	vuln, err := s.vulnDB.GetByID(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("vulnerability not found")
	}

	scan, err := s.scanDB.GetByID(ctx, vuln.ScanID)
	if err != nil {
		return nil, fmt.Errorf("scan not found")
	}

	if err := s.checkScanOwnership(ctx, scan, userID); err != nil {
		return nil, err
	}

	return vuln, nil
}

func (s *ScanService) GetTargetVulnerabilities(ctx context.Context, targetID, userID, severity string, limit, offset int) ([]*model.Vulnerability, error) {
	target, err := s.targetDB.GetByID(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("target not found")
	}

	p, err := s.projectDB.GetByID(ctx, target.ProjectID)
	if err != nil {
		return nil, err
	}
	if p.UserID != userID {
		return nil, ErrForbidden
	}

	return s.vulnDB.ListByTarget(ctx, targetID, severity, limit, offset)
}

func (s *ScanService) GetDashboard(ctx context.Context, userID string) (*model.DashboardStats, error) {
	scans, err := s.scanDB.ListByUser(ctx, userID, 10, 0)
	if err != nil {
		return nil, err
	}

	stats := &model.DashboardStats{
		RecentScans: scans,
	}

	targetCount, _ := s.targetDB.CountByUser(ctx, userID)
	stats.TotalTargets = targetCount

	stats.TotalScans = len(scans)
	for _, sc := range scans {
		stats.TotalVulnerabilities += sc.TotalFindings
		stats.CriticalCount += sc.CriticalCount
		stats.HighCount += sc.HighCount
		stats.MediumCount += sc.MediumCount
		stats.LowCount += sc.LowCount
		stats.InfoCount += sc.InfoCount
	}

	return stats, nil
}

func (s *ScanService) UpdateVulnerabilityStatus(ctx context.Context, vulnID, userID, status string) error {
	vuln, err := s.vulnDB.GetByID(ctx, vulnID)
	if err != nil {
		return fmt.Errorf("vulnerability not found")
	}

	scan, err := s.scanDB.GetByID(ctx, vuln.ScanID)
	if err != nil {
		return err
	}

	if err := s.checkScanOwnership(ctx, scan, userID); err != nil {
		return err
	}

	return s.vulnDB.UpdateStatus(ctx, vulnID, status)
}

func (s *ScanService) checkScanOwnership(ctx context.Context, scan *model.Scan, userID string) error {
	target, err := s.targetDB.GetByID(ctx, scan.TargetID)
	if err != nil {
		return err
	}
	p, err := s.projectDB.GetByID(ctx, target.ProjectID)
	if err != nil {
		return err
	}
	if p.UserID != userID {
		return ErrForbidden
	}
	return nil
}

// ImportCLIScan stores a scan that ran in the CLI (e.g. in CI) as a new,
// completed scan on a target the caller owns. The server always creates the
// scan row: accepting a client-supplied scan ID would let one user write into
// another user's scan.
func (s *ScanService) ImportCLIScan(ctx context.Context, userID, targetID string, vulns []*model.Vulnerability, pagesCrawled, durationSec int) (*model.Scan, error) {
	target, err := s.targetDB.GetByID(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("target not found")
	}
	p, err := s.projectDB.GetByID(ctx, target.ProjectID)
	if err != nil {
		return nil, err
	}
	if p.UserID != userID {
		// Same answer as a missing target, so IDs of other users' targets can't be probed.
		return nil, fmt.Errorf("target not found")
	}

	scanCount, err := s.scanDB.CountByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if scanCount >= model.PlanConfig[s.getUserPlan(ctx, userID)].MaxScans {
		return nil, ErrPlanLimit
	}

	scan := &model.Scan{TargetID: targetID, Status: "running", Config: `{"source":"cli"}`}
	if err := s.scanDB.Create(ctx, scan); err != nil {
		return nil, err
	}

	for _, v := range vulns {
		v.ScanID = scan.ID
		v.TargetID = targetID
		switch v.Severity {
		case "CRITICAL":
			scan.CriticalCount++
		case "HIGH":
			scan.HighCount++
		case "MEDIUM":
			scan.MediumCount++
		case "LOW":
			scan.LowCount++
		default:
			v.Severity = "INFO"
			scan.InfoCount++
		}
		if err := s.vulnDB.Create(ctx, v); err != nil {
			_ = s.scanDB.FailScan(ctx, scan.ID, "import failed: "+err.Error())
			return nil, err
		}
	}

	scan.PagesCrawled = pagesCrawled
	scan.TotalFindings = len(vulns)
	scan.Status = "completed"
	startedAt := time.Now().Add(-time.Duration(durationSec) * time.Second)
	scan.StartedAt = &startedAt
	if err := s.scanDB.CompleteScan(ctx, scan); err != nil {
		return nil, err
	}
	return scan, nil
}
