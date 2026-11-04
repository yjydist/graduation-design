package ledger

import (
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func TestFreshnessWallBoundaries(t *testing.T) {
	for _, test := range []struct {
		name      string
		now       time.Time
		timestamp uint64
		want      string
	}{
		{"age-at-limit", time.Unix(105, 0), 100, ""},
		{"age-over-limit", time.Unix(105, 1), 100, "STATE_STALE"},
		{"future-at-tolerance", time.Unix(100, 0), 101, ""},
		{"future-over-tolerance", time.Unix(99, 999999999), 101, "BLOCK_TIME_FUTURE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &manualClock{wall: test.now}
			r := NewStateReader(nil, &Deployment{DeploymentID: "test"}, t.TempDir(), c)
			err := r.fresh(&Header{Hash: common.Hash{1}, Timestamp: hexutil.Uint64(test.timestamp)})
			if (test.want == "" && err != nil) || (test.want != "" && (err == nil || !strings.HasPrefix(err.Error(), test.want))) {
				t.Fatalf("freshness result %v, expected %s", err, test.want)
			}
		})
	}
}

func TestMonotonicBudgetNotRenewed(t *testing.T) {
	c := &manualClock{wall: time.Unix(100, 0)}
	r := NewStateReader(nil, &Deployment{DeploymentID: "test"}, t.TempDir(), c)
	h := &Header{Hash: common.Hash{1}, Timestamp: 100}
	if err := r.fresh(h); err != nil {
		t.Fatal(err)
	}
	deadline := r.budgets[h.Hash]
	for i := 1; i <= 4; i++ {
		c.wall = time.Unix(100+int64(i), 0)
		c.mono = time.Duration(i) * time.Second
		if err := r.fresh(h); err != nil {
			t.Fatal(err)
		}
		if r.budgets[h.Hash] != deadline {
			t.Fatal("repeated observation renewed budget")
		}
	}
	// A reconnect swaps the transport; the reader retains the original block budget.
	r.Client = nil
	c.wall = time.Unix(104, 0)
	c.mono = 6 * time.Second
	if err := r.fresh(h); err == nil || !strings.HasPrefix(err.Error(), "STATE_STALE") {
		t.Fatal("frozen wall clock extended monotonic lifetime")
	}
}

func TestClockRollbackAndRevalidation(t *testing.T) {
	c := &manualClock{wall: time.Unix(100, 500000000)}
	r := NewStateReader(nil, &Deployment{DeploymentID: "test"}, t.TempDir(), c)
	h := &Header{Hash: common.Hash{1}, Timestamp: 100}
	if err := r.fresh(h); err != nil {
		t.Fatal(err)
	}
	deadline := r.budgets[h.Hash]
	c.wall = time.Unix(100, 400000000)
	c.mono = 100 * time.Millisecond
	if err := r.fresh(h); err == nil || !strings.HasPrefix(err.Error(), "CLOCK_ROLLED_BACK") {
		t.Fatal("wall clock rollback was hidden by monotonic time")
	}
	r.Revalidate()
	c.wall = time.Unix(101, 0)
	c.mono = time.Second
	if err := r.fresh(h); err != nil {
		t.Fatal(err)
	}
	if r.budgets[h.Hash] != deadline {
		t.Fatal("revalidation reset budget")
	}
	c.wall = time.Unix(101, 0)
	c.mono = deadline + time.Nanosecond
	if err := r.fresh(h); err == nil {
		t.Fatal("clock recovery renewed old block")
	}
	newHead := &Header{Hash: common.Hash{2}, Timestamp: 102}
	c.wall = time.Unix(102, 0)
	if err := r.fresh(newHead); err != nil {
		t.Fatalf("fresh new head did not recover: %v", err)
	}
}

func TestFutureBlockBudgetAndStaleRestart(t *testing.T) {
	c := &manualClock{wall: time.Unix(100, 0)}
	r := NewStateReader(nil, &Deployment{DeploymentID: "test"}, t.TempDir(), c)
	h := &Header{Hash: common.Hash{1}, Timestamp: 101}
	if err := r.fresh(h); err != nil {
		t.Fatal(err)
	}
	if r.budgets[h.Hash] != 5*time.Second {
		t.Fatal("future tolerance enlarged budget")
	}
	c.wall = time.Unix(102, 0)
	c.mono = 5*time.Second + time.Nanosecond
	if err := r.fresh(h); err == nil {
		t.Fatal("future observation budget reset")
	}
	c.wall = time.Unix(107, 0)
	if err := NewStateReader(nil, &Deployment{DeploymentID: "test"}, t.TempDir(), c).fresh(h); err == nil || !strings.HasPrefix(err.Error(), "STATE_STALE") {
		t.Fatal("restart renewed stale header")
	}
}
