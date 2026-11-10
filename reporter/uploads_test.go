package reporter

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// largeReport is a valid report whose padding puts it over the size that takes no upload slot.
var largeReport = rateTestReport + strings.Repeat(" ", maxUnslottedBodyBytes)

// holdSlot starts a POST of unknown length and returns once the handler reads its body, so its slot is taken.
// The returned func sends the rest of the body and returns the status code.
func holdSlot(t *testing.T, handler http.HandlerFunc) (finish func() int) {
	t.Helper()
	pr, pw := io.Pipe()
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler(rec, httptest.NewRequest(http.MethodPost, "/", pr))
	}()
	// An io.Pipe write returns only once the handler has read it.
	if _, err := pw.Write([]byte(rateTestReport[:20])); err != nil {
		t.Fatal(err)
	}
	return func() int {
		_, _ = pw.Write([]byte(rateTestReport[20:]))
		_ = pw.Close()
		<-done
		return rec.Code
	}
}

// postLength sends body with the declared length (-1 for unknown) and returns the answer and whether the body was read.
func postLength(handler http.HandlerFunc, body string, length int64, header ...string) (*httptest.ResponseRecorder, bool) {
	spy := &readSpy{r: strings.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, "/", spy)
	req.ContentLength = length
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec, spy.read.Load()
}

func TestMaxConcurrentUploads(t *testing.T) {
	handler := NewHandler(zap.NewNop(), WithMaxConcurrentUploads(2))
	held := []func() int{holdSlot(t, handler), holdSlot(t, handler)}

	before := takeSnapshot(t)
	rec, read := postLength(handler, largeReport, int64(len(largeReport)))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" || read {
		t.Errorf("large upload with every slot held: status %d, Retry-After %q, body read %v; want 503, 1, false",
			rec.Code, rec.Header().Get("Retry-After"), read)
	}
	checkDelta(t, takeSnapshot(t).delta(before), snapshot{"http/POST/503": 1, "rejected/overloaded": 1, "durations": 1})

	tests := []struct {
		name   string
		body   string
		length int64
		header []string
		want   int
	}{
		{"unknown length", rateTestReport, -1, nil, http.StatusServiceUnavailable},
		{"declared length one byte over 64 KiB", largeReport[:maxUnslottedBodyBytes+1], maxUnslottedBodyBytes + 1, nil, http.StatusServiceUnavailable},
		{"declared length of exactly 64 KiB", largeReport[:maxUnslottedBodyBytes], maxUnslottedBodyBytes, nil, http.StatusNoContent},
		{"small report", rateTestReport, int64(len(rateTestReport)), nil, http.StatusNoContent},
		{"encoded large upload", largeReport, int64(len(largeReport)), []string{"Content-Encoding", "gzip"}, http.StatusUnsupportedMediaType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rec, _ := postLength(handler, tt.body, tt.length, tt.header...); rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
	for method, want := range map[string]int{http.MethodGet: http.StatusOK, http.MethodOptions: http.StatusNoContent} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(method, "/", nil))
		if rec.Code != want {
			t.Errorf("%s with every slot held = %d, want %d", method, rec.Code, want)
		}
	}

	for _, finish := range held {
		if code := finish(); code != http.StatusNoContent {
			t.Errorf("held upload = %d, want 204", code)
		}
	}
	// Both slots are free again.
	held = []func() int{holdSlot(t, handler)}
	if rec, _ := postLength(handler, largeReport, int64(len(largeReport))); rec.Code != http.StatusNoContent {
		t.Errorf("large upload after the slots were freed = %d, want 204", rec.Code)
	}
	held[0]()
}

// A request over the rate limit is answered 429 before it could take a slot.
func TestMaxConcurrentUploadsAfterRateLimit(t *testing.T) {
	clock := newTestClock()
	// A burst of 2: the held upload and the 503 below use it up.
	handler := NewHandler(zap.NewNop(), WithMaxConcurrentUploads(1), WithRateLimit(1), WithClock(clock.now))
	finish := holdSlot(t, handler)
	var codes []int
	for i := 0; i < 2; i++ {
		rec, _ := postLength(handler, largeReport, int64(len(largeReport)))
		codes = append(codes, rec.Code)
	}
	if want := []int{503, 429}; fmt.Sprint(codes) != fmt.Sprint(want) {
		t.Errorf("status codes %v, want %v", codes, want)
	}
	finish()
}

// A panic while a report is handled frees its slot.
func TestMaxConcurrentUploadsPanic(t *testing.T) {
	var panicked atomic.Bool
	core, _ := observer.New(zap.InfoLevel)
	log := zap.New(core, zap.Hooks(func(e zapcore.Entry) error {
		if e.Message == "content security policy report submitted" && !panicked.Swap(true) {
			panic("boom")
		}
		return nil
	}))
	handler := NewHandler(log, WithMaxConcurrentUploads(1))
	for _, want := range []int{http.StatusInternalServerError, http.StatusNoContent} {
		if rec, _ := postLength(handler, rateTestReport, -1); rec.Code != want {
			t.Errorf("status = %d, want %d", rec.Code, want)
		}
	}
}

func TestMaxConcurrentUploadsOff(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"no option": NewHandler(zap.NewNop()),
		"zero":      NewHandler(zap.NewNop(), WithMaxConcurrentUploads(0)),
		"negative":  NewHandler(zap.NewNop(), WithMaxConcurrentUploads(-1)),
	} {
		t.Run(name, func(t *testing.T) {
			held := []func() int{holdSlot(t, handler), holdSlot(t, handler), holdSlot(t, handler)}
			if rec, _ := postLength(handler, largeReport, int64(len(largeReport))); rec.Code != http.StatusNoContent {
				t.Errorf("large upload with three in flight = %d, want 204", rec.Code)
			}
			for _, finish := range held {
				finish()
			}
		})
	}
}

// firstRead closes started on the first read of the body.
type firstRead struct {
	io.ReadCloser
	started chan struct{}
	once    bool
}

func (f *firstRead) Read(p []byte) (int, error) {
	if !f.once {
		f.once = true
		close(f.started)
	}
	return f.ReadCloser.Read(p)
}

// Through a real server, a small declared length takes no slot and cannot carry more than it declares.
func TestMaxConcurrentUploadsDeclaredLength(t *testing.T) {
	handler := NewHandler(zap.NewNop(), WithMaxConcurrentUploads(1))
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxUnslottedBodyBytes {
			r.Body = &firstRead{ReadCloser: r.Body, started: started}
		}
		handler(w, r)
	}))
	defer server.Close()
	dial := func() net.Conn {
		conn, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}

	// Short of its declared 1 MiB, so it holds the only slot until the connection closes.
	stalled := dial()
	defer stalled.Close()
	fmt.Fprintf(stalled, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", maxBodyBytes, largeReport)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled upload was never read")
	}

	conn := dial()
	defer conn.Close()
	before := takeSnapshot(t)
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s%s", len(rateTestReport), rateTestReport, strings.Repeat("x", 100<<10))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("small report while the slot is held = %d, want 204", resp.StatusCode)
	}
	if got := takeSnapshot(t).delta(before)["bodyBytes"]; got != float64(len(rateTestReport)) {
		t.Errorf("read %v body bytes, want the declared %d", got, len(rateTestReport))
	}
}
