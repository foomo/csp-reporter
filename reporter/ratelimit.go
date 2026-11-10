package reporter

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// maxClientsPerGeneration bounds the per-client table, which holds at most two generations.
const maxClientsPerGeneration = 10000

// tokenBucket holds up to max(1, 2 × rate) tokens and gains rate tokens per second.
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// refill starts a new bucket full, and ignores a clock that goes backwards.
func (b *tokenBucket) refill(now time.Time, rate float64) {
	burst := max(1, 2*rate)
	if b.last.IsZero() {
		b.tokens = burst
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(burst, b.tokens+elapsed*rate)
	}
	b.last = now
}

type rateLimiter struct {
	now        func() time.Time
	rate       float64
	clientRate float64
	trusted    []netip.Prefix
	maxClients int

	mu     sync.Mutex
	global tokenBucket
	// clients is the current generation; previous is dropped when clients fills up, evicting idle clients.
	clients, previous map[netip.Addr]*tokenBucket
}

func newRateLimiter(o options) *rateLimiter {
	return &rateLimiter{
		now: o.now, rate: o.rate, clientRate: o.clientRate, trusted: o.trustedProxies,
		maxClients: maxClientsPerGeneration, clients: map[netip.Addr]*tokenBucket{},
	}
}

// allow takes a token from the client's bucket and the global one, or from neither when either is empty.
func (l *rateLimiter) allow(r *http.Request) bool {
	var key netip.Addr
	if l.clientRate > 0 {
		key = clientKey(clientAddr(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), l.trusted))
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var client *tokenBucket
	if l.clientRate > 0 {
		// Checked first, so a client over its own limit does not spend the global budget.
		client = l.client(key)
		client.refill(now, l.clientRate)
		if client.tokens < 1 {
			return false
		}
	}
	if l.rate > 0 {
		l.global.refill(now, l.rate)
		if l.global.tokens < 1 {
			return false
		}
		l.global.tokens--
	}
	if client != nil {
		client.tokens--
	}
	return true
}

// client returns the key's bucket, promoting it from the previous generation if it is there.
func (l *rateLimiter) client(key netip.Addr) *tokenBucket {
	if b, ok := l.clients[key]; ok {
		return b
	}
	b, ok := l.previous[key]
	if ok {
		delete(l.previous, key)
	} else {
		b = &tokenBucket{}
	}
	if len(l.clients) >= l.maxClients {
		l.previous, l.clients = l.clients, make(map[netip.Addr]*tokenBucket, len(l.clients))
	}
	l.clients[key] = b
	return b
}

// clientKey groups IPv6 clients by /64, the smallest network an end user is usually given.
func clientKey(addr netip.Addr) netip.Addr {
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().Addr()
	}
	return addr
}

// clientAddr trusts X-Forwarded-For only from a trusted peer, and stops at a malformed entry since all left of it may be forged.
func clientAddr(remoteAddr string, forwardedFor []string, trusted []netip.Prefix) netip.Addr {
	peer := parseAddr(remoteAddr)
	if !isTrusted(peer, trusted) || len(forwardedFor) == 0 {
		return peer
	}
	entries := strings.Split(strings.Join(forwardedFor, ","), ",")
	for i := len(entries) - 1; i >= 0; i-- {
		addr := parseAddr(strings.TrimSpace(entries[i]))
		if !addr.IsValid() {
			return peer
		}
		if !isTrusted(addr, trusted) {
			return addr
		}
	}
	return peer
}

// parseAddr accepts an address with or without a port; IPv4-mapped IPv6 becomes IPv4 and zones are dropped.
func parseAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		addrPort, err := netip.ParseAddrPort(s)
		if err != nil {
			return netip.Addr{}
		}
		addr = addrPort.Addr()
	}
	return addr.Unmap().WithZone("")
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
