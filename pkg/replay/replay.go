// Package replay records HTTP requests/responses to a JSONL file and replays them later.
// Handy when iterating on scanner accuracy against a frozen capture.
package replay

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Entry is one recorded HTTP round-trip.
type Entry struct {
	Time      time.Time         `json:"time"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	ReqHdrs   map[string]string `json:"req_headers,omitempty"`
	ReqBody   string            `json:"req_body,omitempty"` // base64
	Status    int               `json:"status"`
	RespHdrs  map[string]string `json:"resp_headers,omitempty"`
	RespBody  string            `json:"resp_body,omitempty"` // base64
	Duration  string            `json:"duration,omitempty"`
}

// Recorder writes entries to a JSONL file.
type Recorder struct {
	w io.Writer
	f *os.File
}

func NewRecorder(path string) (*Recorder, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &Recorder{w: f, f: f}, nil
}

func (r *Recorder) Close() error { return r.f.Close() }

// RoundTripper wraps an underlying RT and records every transaction.
type RoundTripper struct {
	Underlying http.RoundTripper
	Rec        *Recorder
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	resp, err := rt.Underlying.RoundTrip(req)
	dur := time.Since(start)
	if err != nil {
		return resp, err
	}
	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
	}
	entry := Entry{
		Time:     start,
		Method:   req.Method,
		URL:      req.URL.String(),
		ReqHdrs:  flatten(req.Header),
		ReqBody:  base64.StdEncoding.EncodeToString(reqBody),
		Status:   resp.StatusCode,
		RespHdrs: flatten(resp.Header),
		RespBody: base64.StdEncoding.EncodeToString(respBody),
		Duration: dur.String(),
	}
	b, _ := json.Marshal(entry)
	rt.Rec.w.Write(b)
	rt.Rec.w.Write([]byte("\n"))
	return resp, err
}

func flatten(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// Player feeds recorded entries back through an http.Client (or a custom callback).
// Useful for unit testing scanners against deterministic fixtures.
type Player struct {
	Entries []Entry
}

func Load(path string) (*Player, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return &Player{Entries: entries}, nil
}

// HandlerFunc returns an http.HandlerFunc that responds with the recorded entry whose
// path+query matches the incoming request. Falls back to 404 on miss.
func (p *Player) HandlerFunc() http.HandlerFunc {
	idx := make(map[string]Entry, len(p.Entries))
	for _, e := range p.Entries {
		key := e.URL
		if i := strings.Index(e.URL, "://"); i >= 0 {
			if j := strings.IndexByte(e.URL[i+3:], '/'); j >= 0 {
				key = e.URL[i+3+j:]
			}
		}
		idx[key] = e
	}
	return func(w http.ResponseWriter, r *http.Request) {
		entry, ok := idx[r.URL.RequestURI()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		for k, v := range entry.RespHdrs {
			w.Header().Set(k, v)
		}
		w.WriteHeader(entry.Status)
		body, _ := base64.StdEncoding.DecodeString(entry.RespBody)
		fmt.Fprint(w, string(body))
	}
}
