package harness

import (
	"math"
	"slices"
	"sync"
	"time"
)

// MeasureClockResolutionNs estimates the host wall-clock resolution in
// nanoseconds by observing the minimum positive delta across consecutive
// time.Now calls.
func MeasureClockResolutionNs(samples int) int64 {
	if samples <= 0 {
		samples = 2000
	}
	var minDelta int64
	prev := time.Now().UTC().UnixNano()
	for range samples {
		cur := time.Now().UTC().UnixNano()
		if cur > prev {
			delta := cur - prev
			if minDelta == 0 || delta < minDelta {
				minDelta = delta
			}
			prev = cur
		}
	}
	if minDelta <= 0 {
		return 1000
	}
	return minDelta
}

// LatencyStats holds descriptive latency statistics in milliseconds.
type LatencyStats struct {
	Count  int     `json:"count"`
	MinMs  float64 `json:"minMs"`
	P50Ms  float64 `json:"p50Ms"`
	P95Ms  float64 `json:"p95Ms"`
	P99Ms  float64 `json:"p99Ms"`
	MaxMs  float64 `json:"maxMs"`
	MeanMs float64 `json:"meanMs"`
}

// ComputeLatencyStats computes summary statistics over samplesMs without
// mutating the caller's slice. Non-finite samples (NaN/Inf) are ignored.
func ComputeLatencyStats(samplesMs []float64) LatencyStats {
	valid := make([]float64, 0, len(samplesMs))
	var sum float64
	for _, v := range samplesMs {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		valid = append(valid, v)
		sum += v
	}
	n := len(valid)
	if n == 0 {
		return LatencyStats{}
	}
	slices.Sort(valid)
	return LatencyStats{
		Count:  n,
		MinMs:  valid[0],
		P50Ms:  percentile(valid, 0.50),
		P95Ms:  percentile(valid, 0.95),
		P99Ms:  percentile(valid, 0.99),
		MaxMs:  valid[n-1],
		MeanMs: sum / float64(n),
	}
}

func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return sorted[0]
	}
	pos := p * float64(n-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo] + frac*(sorted[hi]-sorted[lo])
}

// RequestOutcome classifies a recorded experiment request outcome.
type RequestOutcome string

const (
	OutcomeAllow   RequestOutcome = "allow"
	OutcomeDeny    RequestOutcome = "deny"
	OutcomeError   RequestOutcome = "error"
	OutcomeTimeout RequestOutcome = "timeout"
	OutcomeMissed  RequestOutcome = "missed"
	OutcomeDropped RequestOutcome = "dropped"
)

// RequestAccountingSnapshot is a point-in-time serializable view of
// RequestAccounting counters and latency statistics.
type RequestAccountingSnapshot struct {
	Total     int          `json:"total"`
	Allow     int          `json:"allow"`
	Deny      int          `json:"deny"`
	Error     int          `json:"error"`
	Timeout   int          `json:"timeout,omitempty"`
	Missed    int          `json:"missed,omitempty"`
	Dropped   int          `json:"dropped,omitempty"`
	Latencies LatencyStats `json:"latencies"`
}

// RequestAccounting tracks request outcome counts and latencies safely across
// concurrent goroutines. Its zero value is ready to use.
type RequestAccounting struct {
	mu          sync.Mutex
	total       int
	allow       int
	deny        int
	errCount    int
	timeout     int
	missed      int
	dropped     int
	latenciesMs []float64
}

// NewRequestAccounting creates an initialized RequestAccounting instance.
func NewRequestAccounting() *RequestAccounting {
	return &RequestAccounting{}
}

// Record records a request outcome and its latency (negative durations are
// excluded from latency statistics, useful for missed/dropped slots).
func (a *RequestAccounting) Record(outcome RequestOutcome, latency time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.total++
	switch outcome {
	case OutcomeAllow:
		a.allow++
	case OutcomeDeny:
		a.deny++
	case OutcomeError:
		a.errCount++
	case OutcomeTimeout:
		a.timeout++
	case OutcomeMissed:
		a.missed++
	case OutcomeDropped:
		a.dropped++
	default:
		a.errCount++
	}

	if latency >= 0 {
		a.latenciesMs = append(a.latenciesMs, float64(latency)/float64(time.Millisecond))
	}
}

// RecordAllow records an allowed request and its latency.
func (a *RequestAccounting) RecordAllow(latency time.Duration) {
	a.Record(OutcomeAllow, latency)
}

// RecordDeny records a denied request and its latency.
func (a *RequestAccounting) RecordDeny(latency time.Duration) {
	a.Record(OutcomeDeny, latency)
}

// RecordError records an errored request and its latency.
func (a *RequestAccounting) RecordError(latency time.Duration) {
	a.Record(OutcomeError, latency)
}

// Snapshot returns a consistent copy of counters and latency statistics.
func (a *RequestAccounting) Snapshot() RequestAccountingSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	return RequestAccountingSnapshot{
		Total:     a.total,
		Allow:     a.allow,
		Deny:      a.deny,
		Error:     a.errCount,
		Timeout:   a.timeout,
		Missed:    a.missed,
		Dropped:   a.dropped,
		Latencies: ComputeLatencyStats(a.latenciesMs),
	}
}
