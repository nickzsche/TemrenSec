// Package auditlog is an append-only event log with a rolling SHA-256 hash chain.
// Tampering with any historical line breaks every subsequent hash, providing
// detect-only tamper evidence without external dependencies.
package auditlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Event struct {
	Time    time.Time         `json:"time"`
	Actor   string            `json:"actor"`
	Action  string            `json:"action"`
	Object  string            `json:"object,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
	PrevSum string            `json:"prev_sum"`
	Sum     string            `json:"sum"`
}

// Log appends to a file and tracks the most recent checksum.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	last string
	sink *AsyncShipper // nil = no off-system shipping (default)
}

func Open(path string) (*Log, error) {
	last, err := tailHash(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f, last: last}, nil
}

func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	return l.f.Close()
}

// Append writes a new event and returns its computed hash.
func (l *Log) Append(actor, action, object string, data map[string]string) (string, error) {
	if l == nil {
		return "", fmt.Errorf("nil log")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Event{
		Time: time.Now().UTC(), Actor: actor, Action: action, Object: object,
		Data: data, PrevSum: l.last,
	}
	canonical, _ := json.Marshal(struct {
		Time    time.Time         `json:"time"`
		Actor   string            `json:"actor"`
		Action  string            `json:"action"`
		Object  string            `json:"object,omitempty"`
		Data    map[string]string `json:"data,omitempty"`
		PrevSum string            `json:"prev_sum"`
	}{e.Time, e.Actor, e.Action, e.Object, e.Data, e.PrevSum})
	sum := sha256.Sum256(canonical)
	e.Sum = hex.EncodeToString(sum[:])
	line, _ := json.Marshal(e)
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return "", err
	}
	l.last = e.Sum
	// Fire-and-forget ship to off-system sink if configured. Local append
	// is authoritative — Sink failures don't block the caller or the chain.
	if l.sink != nil {
		l.sink.enqueue(e)
	}
	return e.Sum, nil
}

// Verify walks the log and confirms the chain is intact. Returns the first bad line
// (1-based) or 0 if clean.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	var last string
	line := 0
	for sc.Scan() {
		line++
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return line, err
		}
		canonical, _ := json.Marshal(struct {
			Time    time.Time         `json:"time"`
			Actor   string            `json:"actor"`
			Action  string            `json:"action"`
			Object  string            `json:"object,omitempty"`
			Data    map[string]string `json:"data,omitempty"`
			PrevSum string            `json:"prev_sum"`
		}{e.Time, e.Actor, e.Action, e.Object, e.Data, e.PrevSum})
		sum := sha256.Sum256(canonical)
		want := hex.EncodeToString(sum[:])
		if want != e.Sum {
			return line, fmt.Errorf("hash mismatch on line %d", line)
		}
		if e.PrevSum != last {
			return line, fmt.Errorf("prev_sum chain broken at line %d", line)
		}
		last = e.Sum
	}
	return 0, nil
}

func tailHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	var last string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err == nil {
			last = e.Sum
		}
	}
	return last, nil
}

// Tail streams the file's events, useful for live UI.
func Tail(path string, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}
