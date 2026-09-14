// Package policy evaluates simple YAML-defined rules against a set of findings.
// Each rule has a name, a condition (a small expression language), and an action
// (fail/warn/notify/tag). Useful for gating CI builds:
//
//   rules:
//     - name: block-prod-criticals
//       when: severity == "CRITICAL" && asset.tag contains "prod"
//       action: fail
//       message: "Critical finding on production asset"
//
// The expression language supports:
//   identifiers   severity, scanner, url, owasp, cvss, confidence, asset.tag
//   operators     == != > < >= <= && || ! contains startswith endswith
//   literals      "strings", numbers, true/false
//   grouping      (a || b) && c
package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/temren/pkg/scanner"
	"gopkg.in/yaml.v3"
)

type Action string

const (
	ActionFail   Action = "fail"
	ActionWarn   Action = "warn"
	ActionNotify Action = "notify"
	ActionTag    Action = "tag"
)

// Rule is one policy entry.
type Rule struct {
	Name    string `yaml:"name"`
	When    string `yaml:"when"`
	Action  Action `yaml:"action"`
	Message string `yaml:"message,omitempty"`
	Tag     string `yaml:"tag,omitempty"` // used by ActionTag
}

// Policy is a list of rules loaded from YAML.
type Policy struct {
	Rules []Rule `yaml:"rules"`
}

// Decision is one rule's verdict for one finding.
type Decision struct {
	Rule    string
	Action  Action
	Message string
	Finding scanner.Finding
}

// Load decodes YAML bytes into a Policy.
func Load(b []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Evaluate runs every rule against every finding.
func (p *Policy) Evaluate(findings []scanner.Finding, assetTags []string) ([]Decision, error) {
	var out []Decision
	for _, f := range findings {
		env := buildEnv(f, assetTags)
		for _, r := range p.Rules {
			matched, err := eval(r.When, env)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.Name, err)
			}
			if matched {
				out = append(out, Decision{Rule: r.Name, Action: r.Action, Message: r.Message, Finding: f})
			}
		}
	}
	return out, nil
}

// HasFailure reports whether any decision is a fail action — useful in CLI exit codes.
func HasFailure(decisions []Decision) bool {
	for _, d := range decisions {
		if d.Action == ActionFail {
			return true
		}
	}
	return false
}

func buildEnv(f scanner.Finding, tags []string) map[string]any {
	return map[string]any{
		"severity":   string(f.Severity),
		"scanner":    f.Scanner,
		"url":        f.URL,
		"owasp":      f.OWASPCategory,
		"cvss":       f.CVSSScore,
		"confidence": string(f.Confidence),
		"asset.tag":  tags,
	}
}

// --- tiny expression evaluator (recursive-descent) ---

type parser struct {
	tokens []token
	pos    int
}

type tokenKind int

const (
	tkIdent tokenKind = iota
	tkStr
	tkNum
	tkBool
	tkOp
	tkLParen
	tkRParen
)

type token struct {
	kind tokenKind
	str  string
}

func tokenize(src string) ([]token, error) {
	var out []token
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(':
			out = append(out, token{tkLParen, "("})
			i++
		case c == ')':
			out = append(out, token{tkRParen, ")"})
			i++
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(src) && src[j] != c {
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("unterminated string at %d", i)
			}
			out = append(out, token{tkStr, src[i+1 : j]})
			i = j + 1
		case isIdentStart(c):
			j := i
			for j < len(src) && (isIdentStart(src[j]) || src[j] == '.' || (src[j] >= '0' && src[j] <= '9')) {
				j++
			}
			word := src[i:j]
			switch word {
			case "true", "false":
				out = append(out, token{tkBool, word})
			case "contains", "startswith", "endswith":
				out = append(out, token{tkOp, word})
			default:
				out = append(out, token{tkIdent, word})
			}
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && ((src[j] >= '0' && src[j] <= '9') || src[j] == '.') {
				j++
			}
			out = append(out, token{tkNum, src[i:j]})
			i = j
		case c == '&' && i+1 < len(src) && src[i+1] == '&':
			out = append(out, token{tkOp, "&&"})
			i += 2
		case c == '|' && i+1 < len(src) && src[i+1] == '|':
			out = append(out, token{tkOp, "||"})
			i += 2
		case c == '=' && i+1 < len(src) && src[i+1] == '=':
			out = append(out, token{tkOp, "=="})
			i += 2
		case c == '!' && i+1 < len(src) && src[i+1] == '=':
			out = append(out, token{tkOp, "!="})
			i += 2
		case c == '!':
			out = append(out, token{tkOp, "!"})
			i++
		case c == '>' && i+1 < len(src) && src[i+1] == '=':
			out = append(out, token{tkOp, ">="})
			i += 2
		case c == '<' && i+1 < len(src) && src[i+1] == '=':
			out = append(out, token{tkOp, "<="})
			i += 2
		case c == '>':
			out = append(out, token{tkOp, ">"})
			i++
		case c == '<':
			out = append(out, token{tkOp, "<"})
			i++
		default:
			return nil, fmt.Errorf("unexpected character %q at %d", c, i)
		}
	}
	return out, nil
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func eval(expr string, env map[string]any) (bool, error) {
	if strings.TrimSpace(expr) == "" {
		return true, nil
	}
	toks, err := tokenize(expr)
	if err != nil {
		return false, err
	}
	p := &parser{tokens: toks}
	v, err := p.parseOr(env)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expression did not evaluate to bool: %v", v)
	}
	return b, nil
}

func (p *parser) peek() *token {
	if p.pos >= len(p.tokens) {
		return nil
	}
	return &p.tokens[p.pos]
}
func (p *parser) next() token { t := p.tokens[p.pos]; p.pos++; return t }

func (p *parser) parseOr(env map[string]any) (any, error) {
	left, err := p.parseAnd(env)
	if err != nil {
		return nil, err
	}
	for p.peek() != nil && p.peek().str == "||" {
		p.next()
		right, err := p.parseAnd(env)
		if err != nil {
			return nil, err
		}
		left = toBool(left) || toBool(right)
	}
	return left, nil
}

func (p *parser) parseAnd(env map[string]any) (any, error) {
	left, err := p.parseUnary(env)
	if err != nil {
		return nil, err
	}
	for p.peek() != nil && p.peek().str == "&&" {
		p.next()
		right, err := p.parseUnary(env)
		if err != nil {
			return nil, err
		}
		left = toBool(left) && toBool(right)
	}
	return left, nil
}

func (p *parser) parseUnary(env map[string]any) (any, error) {
	if p.peek() != nil && p.peek().str == "!" {
		p.next()
		v, err := p.parseUnary(env)
		if err != nil {
			return nil, err
		}
		return !toBool(v), nil
	}
	return p.parseCompare(env)
}

func (p *parser) parseCompare(env map[string]any) (any, error) {
	left, err := p.parsePrimary(env)
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t != nil && t.kind == tkOp {
		switch t.str {
		case "==", "!=", ">", "<", ">=", "<=", "contains", "startswith", "endswith":
			p.next()
			right, err := p.parsePrimary(env)
			if err != nil {
				return nil, err
			}
			return compare(left, right, t.str), nil
		}
	}
	return left, nil
}

func (p *parser) parsePrimary(env map[string]any) (any, error) {
	t := p.peek()
	if t == nil {
		return nil, fmt.Errorf("unexpected end of expression")
	}
	switch t.kind {
	case tkLParen:
		p.next()
		v, err := p.parseOr(env)
		if err != nil {
			return nil, err
		}
		if p.peek() == nil || p.peek().kind != tkRParen {
			return nil, fmt.Errorf("missing )")
		}
		p.next()
		return v, nil
	case tkStr:
		p.next()
		return t.str, nil
	case tkNum:
		p.next()
		f, _ := strconv.ParseFloat(t.str, 64)
		return f, nil
	case tkBool:
		p.next()
		return t.str == "true", nil
	case tkIdent:
		p.next()
		v, ok := env[t.str]
		if !ok {
			return "", nil
		}
		return v, nil
	}
	return nil, fmt.Errorf("unexpected token %v", t)
}

func toBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	}
	return v != nil
}

func compare(l, r any, op string) bool {
	// Membership / string ops
	switch op {
	case "contains":
		switch ls := l.(type) {
		case string:
			rs, _ := r.(string)
			return strings.Contains(ls, rs)
		case []string:
			rs, _ := r.(string)
			for _, s := range ls {
				if strings.EqualFold(s, rs) {
					return true
				}
			}
		}
		return false
	case "startswith":
		ls, _ := l.(string)
		rs, _ := r.(string)
		return strings.HasPrefix(ls, rs)
	case "endswith":
		ls, _ := l.(string)
		rs, _ := r.(string)
		return strings.HasSuffix(ls, rs)
	}

	lf, lOK := asFloat(l)
	rf, rOK := asFloat(r)
	if lOK && rOK {
		switch op {
		case "==":
			return lf == rf
		case "!=":
			return lf != rf
		case ">":
			return lf > rf
		case "<":
			return lf < rf
		case ">=":
			return lf >= rf
		case "<=":
			return lf <= rf
		}
	}
	ls := fmt.Sprintf("%v", l)
	rs := fmt.Sprintf("%v", r)
	switch op {
	case "==":
		return ls == rs
	case "!=":
		return ls != rs
	}
	return false
}

func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}
