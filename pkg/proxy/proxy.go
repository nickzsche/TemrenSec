// Package proxy provides a minimal HTTP proxy that records every request/response
// for offline analysis. CONNECT (HTTPS tunnels) is supported as a raw byte pump;
// only TLS handshake metadata is captured, never the encrypted body.
package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Listener wraps a Recorder around a stock http.Server.
type Listener struct {
	Addr    string
	OnEntry func(Entry) // optional callback per recorded transaction
}

// Entry is a captured transaction.
type Entry struct {
	When     time.Time
	Method   string
	URL      string
	Status   int
	Bytes    int64
	Duration time.Duration
}

// Run starts the proxy. Blocks until stop is closed.
func (l *Listener) Run(stop <-chan struct{}) error {
	srv := &http.Server{
		Addr:    l.Addr,
		Handler: http.HandlerFunc(l.routeRoot),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

func (l *Listener) routeRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		l.handleConnect(w, r)
		return
	}
	l.handle(w, r)
}

func (l *Listener) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	r.RequestURI = ""
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	if l.OnEntry != nil {
		l.OnEntry(Entry{
			When: start, Method: r.Method, URL: r.URL.String(),
			Status: resp.StatusCode, Bytes: n, Duration: time.Since(start),
		})
	}
}

func (l *Listener) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	upstream, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		upstream.Close()
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()
	brw.WriteString("HTTP/1.1 200 OK\r\n\r\n")
	brw.Flush()
	var bytes int64
	var mu sync.Mutex
	transfer := func(dst, src net.Conn) {
		n, _ := io.Copy(dst, src)
		mu.Lock()
		bytes += n
		mu.Unlock()
	}
	done := make(chan struct{}, 2)
	go func() { transfer(client, upstream); done <- struct{}{} }()
	go func() { transfer(upstream, client); done <- struct{}{} }()
	<-done
	if l.OnEntry != nil {
		l.OnEntry(Entry{
			When: start, Method: "CONNECT", URL: "https://" + r.Host,
			Status: 200, Bytes: bytes, Duration: time.Since(start),
		})
	}
}
