package reporter

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// decodeAllocBudget leaves room for the race detector, which allocates far more than a normal
// build; decoding a whole 1 MiB batch at once allocated over 300 MiB.
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
