// Package templates is a Nuclei-style YAML detection engine: users (and the
// bundled set) describe an HTTP request plus matchers, and the engine runs them
// against a target. It is deliberately standalone — it imports no scanner code,
// so pkg/scanner can adapt its results without an import cycle.
package templates

import (
	"regexp"
	"strings"
)

// Template is one detection: metadata + one or more request blocks.
type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"requests"`
}

type Info struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"` // critical|high|medium|low|info
	Description string   `yaml:"description"`
	Tags        string   `yaml:"tags"`
	Reference   []string `yaml:"reference"`
	OWASP       string   `yaml:"owasp"` // optional 2021 tag, e.g. "A05:2021"
	Remediation string   `yaml:"remediation"`
}

// Request is a single HTTP probe with matchers. Path entries may contain the
// {{BaseURL}} placeholder, which is replaced with the scan target.
type Request struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	MatchersCondition string            `yaml:"matchers-condition"` // and|or (default or)
	Matchers          []Matcher         `yaml:"matchers"`
	Extractors        []Extractor       `yaml:"extractors"`
}

// Extractor pulls data out of a matched response (e.g. a version string or a
// header value) — nuclei-style, surfaced in the finding evidence.
type Extractor struct {
	Type  string   `yaml:"type"` // regex|kval (default regex)
	Part  string   `yaml:"part"` // body|header|all (default body)
	Regex []string `yaml:"regex"`
	Group int      `yaml:"group"` // capture group index (default 0 = whole match)
	KVal  []string `yaml:"kval"`  // header names for type: kval
}

func (e Extractor) extract(r Response) []string {
	var out []string
	if strings.ToLower(e.Type) == "kval" {
		for _, key := range e.KVal {
			for _, line := range strings.Split(r.Header, "\n") {
				if i := strings.Index(line, ":"); i > 0 && strings.EqualFold(strings.TrimSpace(line[:i]), key) {
					out = append(out, strings.TrimSpace(line[i+1:]))
				}
			}
		}
		return uniqStrings(out)
	}
	hay := (Matcher{Part: e.Part}).part(r)
	for _, re := range e.Regex {
		rx, err := regexp.Compile(re)
		if err != nil {
			continue
		}
		for _, m := range rx.FindAllStringSubmatch(hay, -1) {
			if e.Group > 0 && e.Group < len(m) {
				out = append(out, m[e.Group])
			} else {
				out = append(out, m[0])
			}
		}
	}
	return uniqStrings(out)
}

// Extract runs all extractors on a response and returns the collected values.
func (req Request) Extract(r Response) []string {
	var out []string
	for _, e := range req.Extractors {
		out = append(out, e.extract(r)...)
	}
	return uniqStrings(out)
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Matcher evaluates one aspect of a response.
type Matcher struct {
	Type      string   `yaml:"type"` // word|regex|status|header
	Part      string   `yaml:"part"` // body|header|all (default body)
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	Condition string   `yaml:"condition"` // and|or for multi-value (default or)
	Negative  bool     `yaml:"negative"`  // invert the result
}

// Response is the minimal view the matchers need.
type Response struct {
	Status int
	Body   string
	Header string // raw "Key: Value\n..." block, lower-cased keys not required
}

func (m Matcher) part(r Response) string {
	switch strings.ToLower(m.Part) {
	case "header":
		return r.Header
	case "all", "response":
		return r.Header + "\n" + r.Body
	default:
		return r.Body
	}
}

// eval returns whether this matcher matches the response (before Negative).
func (m Matcher) evalRaw(r Response) bool {
	and := strings.ToLower(m.Condition) == "and"
	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if r.Status == s {
				return true
			}
		}
		return false
	case "word":
		hay := m.part(r)
		return matchList(m.Words, and, func(w string) bool { return strings.Contains(hay, w) })
	case "regex":
		hay := m.part(r)
		return matchList(m.Regex, and, func(re string) bool {
			rx, err := regexp.Compile(re)
			return err == nil && rx.MatchString(hay)
		})
	case "header":
		hay := r.Header
		return matchList(m.Words, and, func(w string) bool { return strings.Contains(hay, w) })
	}
	return false
}

// Match applies the matcher including the Negative flag.
func (m Matcher) Match(r Response) bool {
	got := m.evalRaw(r)
	if m.Negative {
		return !got
	}
	return got
}

func matchList(items []string, and bool, pred func(string) bool) bool {
	if len(items) == 0 {
		return false
	}
	for _, it := range items {
		ok := pred(it)
		if and && !ok {
			return false
		}
		if !and && ok {
			return true
		}
	}
	return and // and → all passed; or → none passed
}

// Matches evaluates a whole request block's matchers with its condition.
func (req Request) Matches(r Response) bool {
	if len(req.Matchers) == 0 {
		return false
	}
	and := strings.ToLower(req.MatchersCondition) == "and"
	for _, m := range req.Matchers {
		ok := m.Match(r)
		if and && !ok {
			return false
		}
		if !and && ok {
			return true
		}
	}
	return and
}
