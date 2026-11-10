package reporter

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// decodeAllocBudget is loose enough for the race detector yet far below decoding the whole batch at once.
const decodeAllocBudget = 96 << 20

func TestDecodeReportsAllocations(t *testing.T) {
	for name, entry := range map[string]string{"numbers": "0", "empty objects": "{}"} {
		t.Run(name, func(t *testing.T) {
			n := (maxBodyBytes - 2) / (len(entry) + 1)
			body := []byte("[" + strings.Repeat(entry+",", n-1) + entry + "]")
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, _, err := decodeReports(bytes.NewReader(body))
			runtime.ReadMemStats(&after)
			if !errors.Is(err, errUnknownReport) {
				t.Fatalf("err = %v, want %v", err, errUnknownReport)
			}
			if got := after.TotalAlloc - before.TotalAlloc; got > decodeAllocBudget {
				t.Errorf("decoding a %d byte batch allocated %d MiB, budget %d MiB", len(body), got>>20, decodeAllocBudget>>20)
			}
		})
	}
}
