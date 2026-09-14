// Package scantemplate loads a user-defined scan template from YAML. Templates
// pin a profile, override individual scanners, set custom headers/cookies for
// authentication, and define notification routing.
package scantemplate

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Template struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Profile     string            `yaml:"profile,omitempty"`
	Targets     []string          `yaml:"targets"`
	Scanners    []string          `yaml:"scanners,omitempty"`
	Skip        []string          `yaml:"skip,omitempty"`
	Headers     map[string]string `yaml:"headers,omitempty"`
	Cookies     map[string]string `yaml:"cookies,omitempty"`
	Auth        *Auth             `yaml:"auth,omitempty"`
	Notify      []string          `yaml:"notify,omitempty"`
	PolicyFile  string            `yaml:"policy,omitempty"`
	Tags        []string          `yaml:"tags,omitempty"`
	Schedule    string            `yaml:"schedule,omitempty"` // cron expression
}

type Auth struct {
	Type     string `yaml:"type"` // basic | bearer | cookie | form
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Token    string `yaml:"token,omitempty"`
	LoginURL string `yaml:"login_url,omitempty"`
}

// Load parses YAML bytes into a Template.
func Load(b []byte) (*Template, error) {
	var t Template
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	if len(t.Targets) == 0 {
		return nil, fmt.Errorf("template needs at least one target")
	}
	return &t, nil
}

// LoadFile reads and parses a template file.
func LoadFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}

// Validate reports issues that would prevent a clean scan.
func (t *Template) Validate() error {
	if t.Name == "" {
		return fmt.Errorf("template needs a name")
	}
	if t.Auth != nil {
		switch t.Auth.Type {
		case "", "basic", "bearer", "cookie", "form":
		default:
			return fmt.Errorf("unknown auth type %q", t.Auth.Type)
		}
		if t.Auth.Type == "basic" && (t.Auth.Username == "" || t.Auth.Password == "") {
			return fmt.Errorf("basic auth requires username + password")
		}
		if t.Auth.Type == "bearer" && t.Auth.Token == "" {
			return fmt.Errorf("bearer auth requires token")
		}
		if t.Auth.Type == "form" && t.Auth.LoginURL == "" {
			return fmt.Errorf("form auth requires login_url")
		}
	}
	return nil
}
