package httpengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFormLogin_CapturesSessionCookie(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("username") == "admin" && r.FormValue("password") == "secret" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123", Path: "/"})
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	})
	var gotSession string
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil {
			gotSession = c.Value
		}
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(DefaultConfig())
	err := c.FormLogin(context.Background(), srv.URL+"/login", map[string]string{
		"username": "admin",
		"password": "secret",
	})
	if err != nil {
		t.Fatalf("FormLogin failed: %v", err)
	}

	resp, err := c.Get(context.Background(), srv.URL+"/protected")
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}
	resp.Body.Close()
	if gotSession != "abc123" {
		t.Fatalf("expected session cookie to be sent, got %q", gotSession)
	}
}

func TestFormLogin_NoCookieIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200) // no Set-Cookie
	}))
	defer srv.Close()
	c := NewClient(DefaultConfig())
	if err := c.FormLogin(context.Background(), srv.URL+"/login", map[string]string{"u": "x"}); err == nil {
		t.Fatal("expected error when no session cookie is set")
	}
}

func TestApply_AdditiveCookieAndToken(t *testing.T) {
	cfg := &AuthConfig{
		Method:      AuthMethodCookie,
		Token:       "tok",
		TokenHeader: "Authorization",
		Cookies:     []*http.Cookie{{Name: "session", Value: "v"}},
		Headers:     map[string]string{"X-CSRF": "csrf1"},
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	cfg.Apply(req)

	if got := req.Header.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("expected bearer token applied alongside cookies, got %q", got)
	}
	if c, err := req.Cookie("session"); err != nil || c.Value != "v" {
		t.Errorf("expected session cookie applied, got %v", err)
	}
	if got := req.Header.Get("X-CSRF"); got != "csrf1" {
		t.Errorf("expected custom header applied, got %q", got)
	}
}
