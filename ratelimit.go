package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter throttles repeated failed authentication attempts (wrong
// admin/poll password) per client. It intentionally only counts failures,
// never successful requests or requests carrying no credential at all (e.g.
// the first, expected visit to a locked poll) - so legitimate concurrent use
// from a shared office IP isn't penalized, only active guessing is.
type rateLimiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string][]time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{max: max, window: window, failures: map[string][]time.Time{}}
	go rl.sweepLoop()
	return rl
}

// blocked reports whether key has already hit the failure limit within the
// current window. Checking does not itself count as an attempt.
func (rl *rateLimiter) blocked(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.prune(key, time.Now())) >= rl.max
}

// fail records a failed attempt for key.
func (rl *rateLimiter) fail(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	rl.failures[key] = append(rl.prune(key, now), now)
}

// prune drops (and persists) timestamps older than the window for key,
// returning what's left. Caller must hold rl.mu.
func (rl *rateLimiter) prune(key string, now time.Time) []time.Time {
	kept := rl.failures[key][:0]
	for _, t := range rl.failures[key] {
		if now.Sub(t) < rl.window {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(rl.failures, key)
		return nil
	}
	rl.failures[key] = kept
	return kept
}

// sweepLoop periodically prunes every key so that IPs which failed once and
// never came back don't accumulate in memory forever.
func (rl *rateLimiter) sweepLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key := range rl.failures {
			rl.prune(key, now)
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the connecting IP for rate-limit bucketing.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// credentialSupplied reports whether the request carries an explicit
// password/admin-password credential (header or query), as opposed to no
// credential at all - which is the normal, expected path the first time
// someone opens a locked poll and must not count as a guessing attempt.
func credentialSupplied(r *http.Request) bool {
	return suppliedPassword(r) != "" ||
		r.Header.Get("X-Admin-Password") != "" ||
		r.URL.Query().Get("adminPassword") != ""
}

func writeRateLimitedHTML(w http.ResponseWriter) {
	http.Error(w, "Zu viele Versuche, bitte später erneut versuchen.", http.StatusTooManyRequests)
}

func writeRateLimitedJSON(w http.ResponseWriter) {
	writeJSONError(w, http.StatusTooManyRequests, "Zu viele Versuche, bitte später erneut versuchen")
}
