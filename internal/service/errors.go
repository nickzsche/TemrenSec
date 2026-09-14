package service

import "errors"

var (
	ErrForbidden = errors.New("access denied")
	ErrPlanLimit = errors.New("plan limit reached")
)
