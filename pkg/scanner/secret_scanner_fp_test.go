package scanner

import (
	"strings"
	"testing"
)

// TestSecretScanner_CredentialsInURL_RejectsMinifiedJS asserts that the
// "Credentials in URL" pattern does not light up on minified Next.js
// bundles. The old loose pattern `://[^:]+:[^@]+@` matched any chunk
// containing e.g. `t="@` after a `://...:` substring.
func TestSecretScanner_CredentialsInURL_RejectsMinifiedJS(t *testing.T) {
	s := &SecretScanner{}
	body := `(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[3672],{8612:(e,t,r)=>{"use strict";r.d(t,{w:()=>n});let n=({d:e,fill:t="@aria-label"})=>r.createElement("svg",{viewBox:"0 0 24 24",xmlns:"http://www.w3.org/2000/svg",fill:t})}}]);`
	got := s.scanBody(body, "https://sigortapedia.com/_next/static/chunks/10u3y4bw1ayzs.js", "response body")
	for _, f := range got {
		if strings.Contains(f.Title, "Credentials in URL") {
			t.Errorf("minified JS produced Credentials-in-URL FP: evidence=%q", f.Evidence)
		}
	}
}

// TestSecretScanner_CredentialsInURL_AcceptsRealMongoString asserts that
// a legitimate connection string with embedded credentials IS still flagged.
func TestSecretScanner_CredentialsInURL_AcceptsRealMongoString(t *testing.T) {
	s := &SecretScanner{}
	body := `MONGO_URI=mongodb+srv://admin:hunter2@cluster0.mongodb.net/prod?retryWrites=true`
	got := s.scanBody(body, "/.env", "exposed file: /.env")
	hit := false
	for _, f := range got {
		if strings.Contains(f.Title, "Credentials in URL") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("real mongodb credentials in URL were missed: findings=%+v", got)
	}
}

// TestSecretScanner_CredentialsInURL_AcceptsRealPostgresString covers the
// other common case — Postgres connection string with creds.
func TestSecretScanner_CredentialsInURL_AcceptsRealPostgresString(t *testing.T) {
	s := &SecretScanner{}
	body := `DATABASE_URL=postgres://app_user:Sup3rSecret!@db.internal:5432/app`
	got := s.scanBody(body, "/.env", "exposed file: /.env")
	hit := false
	for _, f := range got {
		if strings.Contains(f.Title, "Credentials in URL") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("real postgres credentials were missed: findings=%+v", got)
	}
}

// TestSecretScanner_IsStaticAssetURL asserts the static-asset
// filter classifies build artifacts correctly.
func TestSecretScanner_IsStaticAssetURL(t *testing.T) {
	cases := []struct {
		url    string
		static bool
	}{
		{"https://x.com/_next/static/chunks/abc.js", true},
		{"https://x.com/static/main.css", true},
		{"https://x.com/font.woff2?v=2", true},
		{"https://x.com/img.png#ref", true},
		{"https://x.com/api/users", false},
		{"https://x.com/.env", false},
		{"https://x.com/", false},
	}
	for _, c := range cases {
		if got := IsStaticAssetURL(c.url); got != c.static {
			t.Errorf("IsStaticAssetURL(%q) = %v, want %v", c.url, got, c.static)
		}
	}
}
