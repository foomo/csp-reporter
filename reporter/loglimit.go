package reporter

import (
	"hash/maphash"
	"sync"
	"time"
)

const (
	// maxReportLinesPerSecond caps report lines across all keys.
	maxReportLinesPerSecond = 100
	// maxLogKeysPerSecond caps the keys tracked within one second.
	maxLogKeysPerSecond = 1000
)

// logLimiter allows perKey report lines per key and second; keys are hashed, so a long URI costs no memory.
type logLimiter struct {
	now      func() time.Time
	perKey   int
	maxLines int
	maxKeys  int
	seed     maphash.Seed

	mu     sync.Mutex
	second int64
	lines  int
	counts map[uint64]int
}

func newLogLimiter(o options) *logLimiter {
	return &logLimiter{
		now: o.now, perKey: o.logLimitPerKey, maxLines: maxReportLinesPerSecond, maxKeys: maxLogKeysPerSecond,
		seed: maphash.MakeSeed(), counts: map[uint64]int{},
	}
}

// allow checks the key's own limit before the total, and counts only written lines against the total.
func (l *logLimiter) allow(key string) bool {
	h := maphash.String(l.seed, key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if second := l.now().Unix(); second != l.second {
		l.second, l.lines = second, 0
		clear(l.counts)
	}
	n, tracked := l.counts[h]
	if !tracked && len(l.counts) >= l.maxKeys {
		return false
	}
	if n >= l.perKey || l.lines >= l.maxLines {
		l.counts[h] = n
		return false
	}
	l.counts[h] = n + 1
	l.lines++
	return true
}
