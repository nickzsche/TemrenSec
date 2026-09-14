package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestProxyRecordsHTTPTransaction(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("hello"))
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	var (
		entries []Entry
		mu      sync.Mutex
	)
	lst := &Listener{Addr: addr, OnEntry: func(e Entry) {
		mu.Lock()
		entries = append(entries, e)
		mu.Unlock()
	}}
	stop := make(chan struct{})
	go func() { _ = lst.Run(stop) }()
	defer close(stop)
	time.Sleep(150 * time.Millisecond)

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello" || resp.StatusCode != http.StatusTeapot {
		t.Errorf("bad response: %d %q", resp.StatusCode, body)
	}

	mu.Lock()
	count := len(entries)
	mu.Unlock()
	if count == 0 {
		t.Fatal("expected at least one captured entry")
	}
}
