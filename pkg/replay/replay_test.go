package replay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecorderAndPlayer(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "trace.jsonl")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	}))
	defer upstream.Close()

	rec, err := NewRecorder(out)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &RoundTripper{Underlying: http.DefaultTransport, Rec: rec}}
	resp, err := cli.Get(upstream.URL + "/a?b=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello" {
		t.Errorf("bad body: %q", body)
	}
	rec.Close()

	stat, _ := os.Stat(out)
	if stat.Size() == 0 {
		t.Fatal("recorder wrote empty file")
	}

	player, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(player.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(player.Entries))
	}
	srv := httptest.NewServer(player.HandlerFunc())
	defer srv.Close()
	resp2, _ := http.Get(srv.URL + "/a?b=1")
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if !strings.Contains(string(body2), "hello") {
		t.Errorf("replay body wrong: %q", body2)
	}
}
