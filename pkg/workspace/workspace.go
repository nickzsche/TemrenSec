// Package workspace groups targets into named workspaces so a single Temren install
// can serve multiple teams without coupling their scan history.
package workspace

import (
	"errors"
	"sort"
	"sync"
	"time"
)

type Target struct {
	URL  string
	Tags []string
	Tier string
}

type Workspace struct {
	Name        string
	Description string
	Targets     []Target
	Created     time.Time
}

type Store struct {
	mu sync.RWMutex
	ws map[string]*Workspace
}

func New() *Store { return &Store{ws: make(map[string]*Workspace)} }

func (s *Store) Create(name, desc string) (*Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ws[name]; ok {
		return nil, errors.New("workspace already exists")
	}
	w := &Workspace{Name: name, Description: desc, Created: time.Now().UTC()}
	s.ws[name] = w
	return w, nil
}

func (s *Store) Get(name string) (*Workspace, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.ws[name]
	return w, ok
}

func (s *Store) Delete(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ws, name)
}

func (s *Store) AddTarget(workspace string, t Target) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.ws[workspace]
	if !ok {
		return errors.New("workspace not found")
	}
	for _, existing := range w.Targets {
		if existing.URL == t.URL {
			return errors.New("target already in workspace")
		}
	}
	w.Targets = append(w.Targets, t)
	return nil
}

func (s *Store) List() []*Workspace {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Workspace, 0, len(s.ws))
	for _, w := range s.ws {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
