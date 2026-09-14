package service

import (
	"context"

	"github.com/temren/internal/database"
	"github.com/temren/internal/model"
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
}

func NewTargetService() *TargetService {
	return &TargetService{
		targetDB:  database.NewTargetRepo(),
		projectDB: database.NewProjectRepo(),
		scanDB:    database.NewScanRepo(),
	}
}

func (s *TargetService) Create(ctx context.Context, userID string, req *model.CreateTargetRequest) (*model.Target, error) {
	project, err := s.projectDB.GetByID(ctx, req.ProjectID)
	if err != nil {
		return nil, err
	}
	_ = project

	targetCount, err := s.targetDB.CountByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	limits := model.PlanConfig["free"]
	if planLimits, ok := model.PlanConfig["pro"]; ok {
		limits = planLimits
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
