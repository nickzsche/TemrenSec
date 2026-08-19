package service

import (
	"context"
	"fmt"

	"github.com/temren/internal/database"
	"github.com/temren/internal/model"
	"github.com/temren/internal/safeurl"
)

type ProjectService struct {
	projectDB *database.ProjectRepo
	targetDB  *database.TargetRepo
}

func NewProjectService() *ProjectService {
	return &ProjectService{
		projectDB: database.NewProjectRepo(),
		targetDB:  database.NewTargetRepo(),
	}
}

func (s *ProjectService) Create(ctx context.Context, userID, name, description string) (*model.Project, error) {
	p := &model.Project{
		UserID:      userID,
		Name:        name,
		Description: description,
	}
	if err := s.projectDB.Create(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *ProjectService) Get(ctx context.Context, id, userID string) (*model.Project, error) {
	p, err := s.projectDB.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.UserID != userID {
		return nil, ErrForbidden
	}
	return p, nil
}

func (s *ProjectService) List(ctx context.Context, userID string) ([]*model.Project, error) {
	return s.projectDB.ListByUser(ctx, userID)
}

func (s *ProjectService) Update(ctx context.Context, id, userID, name, description string) (*model.Project, error) {
	p, err := s.projectDB.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.UserID != userID {
		return nil, ErrForbidden
	}
	p.Name = name
	p.Description = description
	if err := s.projectDB.Update(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *ProjectService) Delete(ctx context.Context, id, userID string) error {
	p, err := s.projectDB.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if p.UserID != userID {
		return ErrForbidden
	}
	return s.projectDB.Delete(ctx, id)
}

type TargetService struct {
	targetDB  *database.TargetRepo
	projectDB *database.ProjectRepo
	scanDB    *database.ScanRepo
	userDB    *database.UserRepo
}

func NewTargetService() *TargetService {
	return &TargetService{
		targetDB:  database.NewTargetRepo(),
		projectDB: database.NewProjectRepo(),
		scanDB:    database.NewScanRepo(),
		userDB:    database.NewUserRepo(),
	}
}

// getUserPlan resolves the caller's plan, defaulting to the most restrictive
// tier if the user cannot be read.
func (s *TargetService) getUserPlan(ctx context.Context, userID string) string {
	user, err := s.userDB.GetByID(ctx, userID)
	if err != nil || user.Plan == "" {
		return "free"
	}
	return user.Plan
}

func (s *TargetService) Create(ctx context.Context, userID string, req *model.CreateTargetRequest) (*model.Target, error) {
	project, err := s.projectDB.GetByID(ctx, req.ProjectID)
	if err != nil {
		return nil, err
	}
	// Every other TargetService method checks this; Create fetched the project
	// and then discarded it, letting any authenticated user add a target to
	// somebody else's project.
	if project.UserID != userID {
		return nil, ErrForbidden
	}

	// The target URL is fetched later by the worker from inside the deployment's
	// network, so it has to be checked before it is ever stored.
	if err := safeurl.Validate(req.URL); err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	targetCount, err := s.targetDB.CountByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Read the caller's actual plan. The previous form always overwrote the
	// free-tier limits with the pro ones, because PlanConfig["pro"] always
	// exists — so quotas were never enforced per plan.
	limits, ok := model.PlanConfig[s.getUserPlan(ctx, userID)]
	if !ok {
		limits = model.PlanConfig["free"]
	}
	if targetCount >= limits.MaxTargets {
		return nil, ErrPlanLimit
	}

	scanSettings := req.ScanSettings
	if scanSettings == "" {
		scanSettings = `{"depth":2,"max_pages":50,"rate_limit":10,"concurrency":5}`
	}

	t := &model.Target{
		ProjectID:    req.ProjectID,
		URL:          req.URL,
		Name:         req.Name,
		ScanSettings: scanSettings,
		Status:       "active",
	}
	if err := s.targetDB.Create(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *TargetService) Get(ctx context.Context, id, userID string) (*model.Target, error) {
	t, err := s.targetDB.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.checkTargetOwnership(ctx, t, userID); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *TargetService) List(ctx context.Context, projectID, userID string) ([]*model.Target, error) {
	p, err := s.projectDB.GetByID(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if p.UserID != userID {
		return nil, ErrForbidden
	}
	return s.targetDB.ListByProject(ctx, projectID)
}

func (s *TargetService) Update(ctx context.Context, id, userID string, req *model.CreateTargetRequest) (*model.Target, error) {
	t, err := s.targetDB.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.checkTargetOwnership(ctx, t, userID); err != nil {
		return nil, err
	}
	if err := safeurl.Validate(req.URL); err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	t.URL = req.URL
	t.Name = req.Name
	t.ScanSettings = req.ScanSettings
	t.Schedule = req.Schedule
	if err := s.targetDB.Update(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *TargetService) Delete(ctx context.Context, id, userID string) error {
	t, err := s.targetDB.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.checkTargetOwnership(ctx, t, userID); err != nil {
		return err
	}
	return s.targetDB.Delete(ctx, id)
}

func (s *TargetService) checkTargetOwnership(ctx context.Context, t *model.Target, userID string) error {
	p, err := s.projectDB.GetByID(ctx, t.ProjectID)
	if err != nil {
		return err
	}
	if p.UserID != userID {
		return ErrForbidden
	}
	return nil
}
