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
					// Soft-404 / catch-all guard. Many sites answer 200 (or a
					// uniform error page that reflects the requested path) for
					// EVERY unknown URL, which makes status-only and
					// reflected-word matchers fire on paths that don't really
					// exist. Before accepting a hit on a specific sub-path, fetch
					// a random sibling in the same directory: if the server
					// answers it the same way (same status, near-identical body),
					// this template's path isn't genuinely present — drop it.
					if isSubPath(url, base) && e.looksLikeSoftMatch(ctx, client, method, url, req, resp) {
						continue
					}
					ev := "Template " + t.ID + " matched (" + method + " " + url + ")"
					if extracted := req.Extract(*resp); len(extracted) > 0 {
						ev += " → " + strings.Join(extracted, ", ")
					}
					out = append(out, Match{
						TemplateID: t.ID, Name: t.Info.Name, Severity: strings.ToUpper(defSev(t.Info.Severity)),
						Description: t.Info.Description, Remediation: t.Info.Remediation, OWASP: t.Info.OWASP,
						References: t.Info.Reference, Tags: t.Info.Tags, URL: url,
						Evidence: ev,
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

// isSubPath reports whether url addresses a specific path under base (not the
// bare base URL). The soft-404 guard only applies to sub-paths — templates
// that probe the root ({{BaseURL}}) legitimately match the real home page.
func isSubPath(url, base string) bool {
	rest := strings.TrimPrefix(url, base)
	rest = strings.TrimPrefix(rest, "/")
	// Ignore a pure query on the root (e.g. base?foo=bar).
	if rest == "" || strings.HasPrefix(rest, "?") {
		return false
	}
	return true
}

// siblingControlURL swaps the last path segment of url for a random token,
// keeping the same directory (and any query string). It is the probe used to
// learn how the server answers a definitely-nonexistent neighbour.
func siblingControlURL(url string) string {
	q := ""
	if i := strings.IndexByte(url, '?'); i >= 0 {
		q = url[i:]
		url = url[:i]
	}
	// Drop a trailing slash so the swap targets the last *named* segment. Without
	// this, ".../campaigns/phpMyAdmin/" would swap the empty segment after the
	// slash (probing one level deeper) instead of a sibling of "phpMyAdmin" —
	// missing soft-200 "not found" pages served at that level.
	trailing := ""
	if strings.HasSuffix(url, "/") {
		trailing = "/"
		url = strings.TrimRight(url, "/")
	}
	tok := "temren-404-" + randToken()
	if i := strings.LastIndexByte(url, '/'); i >= 0 && i >= len("https://") {
		return url[:i+1] + tok + trailing + q
	}
	return url + "/" + tok + trailing + q
}

var softTokenCounter uint64

func randToken() string {
	softTokenCounter++
	// Deterministic-but-unique-per-process token; content doesn't matter, only
	// that the path is one the server has never seen.
	return "x" + itoaBase36(softTokenCounter) + "z9q"
}

func itoaBase36(n uint64) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	var b [13]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%36]
		n /= 36
	}
	return string(b[i:])
}

// looksLikeSoftMatch fetches a random sibling of the matched URL and reports
// whether the real hit is indistinguishable from it — the signature of a
// soft-404 / catch-all page rather than a genuine exposure.
func (e *Engine) looksLikeSoftMatch(ctx context.Context, client *httpengine.Client, method, url string, req Request, hit *Response) bool {
	ctrl := e.fetch(ctx, client, method, siblingControlURL(url), req)
	if ctrl == nil {
		return false // couldn't verify; keep the hit rather than hide it
	}
	if hit.Status != ctrl.Status {
		return false // different status → the path really behaves differently
	}
	return similarLen(len(hit.Body), len(ctrl.Body))
}

// similarLen reports whether two body lengths are within 5% (and 256 bytes) of
// each other — treated as "the same page".
func similarLen(a, b int) bool {
	if a == b {
		return true
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	larger := a
	if b > larger {
		larger = b
	}
	if larger == 0 {
		return true
	}
	if d <= 256 {
		return true
	}
	return float64(d)/float64(larger) <= 0.05
}
