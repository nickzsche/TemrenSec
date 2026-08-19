package spider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/temren/pkg/httpengine"
)

// TestCrawlRespectsConcurrencyLimit — Config.Concurrency was declared, defaulted
// and never read, so the crawler spawned one goroutine per discovered link with
// no ceiling. This measures the peak number of requests in flight.
func TestCrawlRespectsConcurrencyLimit(t *testing.T) {
	const limit = 3

	var (
		mu     sync.Mutex
		inFlt  int
		peak   int
		served atomic.Int64
	)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlt++
		if inFlt > peak {
			peak = inFlt
		}
		mu.Unlock()

		// Hold the connection briefly so overlapping requests are observable.
		time.Sleep(15 * time.Millisecond)

		served.Add(1)
		w.Header().Set("Content-Type", "text/html")
		// Every page links to 8 more, so an uncapped crawler fans out fast.
		fmt.Fprint(w, "<html><body>")
		for i := 0; i < 8; i++ {
			// Derive child paths from the current one so the link graph keeps
			// producing fresh URLs rather than immediately hitting the dedupe set.
			fmt.Fprintf(w, `<a href="%s%s/%d">l</a>`, srv.URL, r.URL.Path, i)
		}
		fmt.Fprint(w, "</body></html>")

		mu.Lock()
		inFlt--
		mu.Unlock()
	}))
	defer srv.Close()

	sp := New(httpengine.NewClient(&httpengine.Config{
		Timeout:         5 * time.Second,
		RateLimit:       1000,
		FollowRedirects: true,
	}), &Config{
		MaxDepth:    3,
		MaxPages:    100,
		Concurrency: limit,
		SameDomain:  true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for range sp.Crawl(ctx, srv.URL) {
	}

	mu.Lock()
	got := peak
	mu.Unlock()

	if served.Load() == 0 {
		t.Fatal("crawler made no requests; the test cannot conclude anything")
	}
	if got > limit {
		t.Errorf("peak concurrent requests = %d, want <= %d (Concurrency is not enforced)", got, limit)
	}
	t.Logf("served %d pages, peak concurrency %d (limit %d)", served.Load(), got, limit)
}

// TestNewDefaultsConcurrencyWhenUnset — a zero value must not mean "unbounded".
func TestNewDefaultsConcurrencyWhenUnset(t *testing.T) {
	sp := New(nil, &Config{MaxDepth: 1, MaxPages: 1})
	if cap(sp.sem) <= 0 {
		t.Fatalf("semaphore capacity = %d, want a positive default", cap(sp.sem))
	}
	if cap(sp.sem) != DefaultConfig().Concurrency {
		t.Errorf("semaphore capacity = %d, want the default %d", cap(sp.sem), DefaultConfig().Concurrency)
	}
}
