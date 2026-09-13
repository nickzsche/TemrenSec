package templates

import (
	"context"
	"embed"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/temren/pkg/httpengine"
	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Match is a template hit against a target — standalone (no scanner import).
type Match struct {
	TemplateID  string
	Name        string
	Severity    string
	Description string
	Remediation string
	OWASP       string
	References  []string
	Tags        string
	URL         string
	Evidence    string
}

// Engine holds parsed templates and runs them against targets.
type Engine struct {
	templates []Template
}

// New loads the bundled templates plus any *.yaml under the given extra dirs
// (e.g. ~/.temren/templates). Malformed files are skipped, not fatal.
func New(extraDirs ...string) *Engine {
	e := &Engine{}
	entries, _ := builtinFS.ReadDir("builtin")
	for _, ent := range entries {
		if data, err := builtinFS.ReadFile("builtin/" + ent.Name()); err == nil {
			e.add(data)
		}
	}
	for _, dir := range extraDirs {
		if dir == "" {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
				if data, rerr := os.ReadFile(path); rerr == nil {
					e.add(data)
				}
			}
			return nil
		})
	}
	return e
}

func (e *Engine) add(data []byte) {
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil || t.ID == "" || len(t.Requests) == 0 {
		return
	}
	e.templates = append(e.templates, t)
}

// Count is how many templates are loaded.
func (e *Engine) Count() int { return len(e.templates) }

// Run executes every template against target and returns the matches.
func (e *Engine) Run(ctx context.Context, target string, client *httpengine.Client) []Match {
	var out []Match
	base := strings.TrimRight(target, "/")
	for _, t := range e.templates {
		for _, req := range t.Requests {
			method := req.Method
			if method == "" {
				method = "GET"
			}
			paths := req.Path
			if len(paths) == 0 {
				paths = []string{"{{BaseURL}}"}
			}
			for _, p := range paths {
				url := strings.ReplaceAll(p, "{{BaseURL}}", base)
				resp := e.fetch(ctx, client, method, url, req)
				if resp == nil {
					continue
				}
				if req.Matches(*resp) {
					out = append(out, Match{
						TemplateID: t.ID, Name: t.Info.Name, Severity: strings.ToUpper(defSev(t.Info.Severity)),
						Description: t.Info.Description, Remediation: t.Info.Remediation, OWASP: t.Info.OWASP,
						References: t.Info.Reference, Tags: t.Info.Tags, URL: url,
						Evidence: "Template " + t.ID + " matched (" + method + " " + url + ")",
					})
					break // one hit per template is enough
				}
			}
		}
	}
	return out
}

func (e *Engine) fetch(ctx context.Context, client *httpengine.Client, method, url string, req Request) *Response {
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	hreq, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}
	hresp, err := client.Do(ctx, hreq)
	if err != nil {
		return nil
	}
	defer hresp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(hresp.Body, 512*1024))
	var hb strings.Builder
	for k, vs := range hresp.Header {
		for _, v := range vs {
			hb.WriteString(k)
			hb.WriteString(": ")
			hb.WriteString(v)
			hb.WriteString("\n")
		}
	}
	return &Response{Status: hresp.StatusCode, Body: string(b), Header: hb.String()}
}

func defSev(s string) string {
	if s == "" {
		return "info"
	}
	return s
}
