package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"grad/protocol"
	"grad/protocol/registry"
)

// ProbeEvidence records a verified original liveness probe observed in the PostgreSQL view
// alongside its monotonic clock send, deadline, and adoption timestamps.
type ProbeEvidence struct {
	TxID         string              `json:"txId"`
	Identity     registry.Management `json:"identity"`
	ProbeBlock   uint64              `json:"probeBlockNumber"`
	View         Point               `json:"view"`
	Sent         time.Time           `json:"sentAt"`
	Deadline     time.Time           `json:"deadline"`
	Adopted      time.Time           `json:"adoptedAt"`
	SentMono     int64               `json:"sentMonoNs"`
	DeadlineMono int64               `json:"deadlineMonoNs"`
	AdoptedMono  int64               `json:"adoptedMonoNs"`
}

// Lease converts ProbeEvidence into the backend-agnostic ProbeLease representation.
func (p ProbeEvidence) Lease() ProbeLease {
	return ProbeLease{
		TxID:           p.TxID,
		ProbeBlock:     p.ProbeBlock,
		SentAt:         p.Sent,
		Deadline:       p.Deadline,
		SentMonoNs:     p.SentMono,
		DeadlineMonoNs: p.DeadlineMono,
		CheckedMonoNs:  p.AdoptedMono,
	}
}

type probeVersionRow struct {
	TxID    string `db:"tx_id"`
	BlockNo uint64 `db:"block_no"`
	Value   []byte `db:"value"`
}

// Start launches the continuous full-block Deliver follower and periodic original probe sender.
// Call the returned stop function to cleanly cancel goroutines and close peer connections.
func (v *Online) Start(ctx context.Context) (func(), error) {
	reader, err := v.Instance.ReadPeer()
	if err != nil {
		return nil, err
	}
	sender, err := v.Instance.Peer(v.Instance.clientOrg, v.Role)
	if err != nil {
		reader.Close()
		return nil, err
	}
	v.started = time.Now()
	v.attempts = map[string]time.Time{}
	v.emit("probe_config", map[string]any{
		"interval":        v.Interval.String(),
		"lifetime":        v.TimeLimit.String(),
		"identity":        sender.role,
		"monotonicOrigin": v.started.UTC(),
	})
	c, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() { v.follow(c, reader) })
	wg.Go(func() { v.probeLoop(c, sender) })
	return func() {
		cancel()
		wg.Wait()
		sender.Close()
		reader.Close()
	}, nil
}

func (v *Online) probeLoop(ctx context.Context, p *PeerClient) {
	ticker := time.NewTicker(v.Interval)
	defer ticker.Stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	busy := make(chan struct{}, 8)
	for {
		select {
		case busy <- struct{}{}:
			wg.Go(func() {
				defer func() { <-busy }()
				if err := v.sendProbe(ctx, p); err != nil && ctx.Err() == nil {
					v.emit("probe_error", err.Error())
				}
			})
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (v *Online) sendProbe(ctx context.Context, p *PeerClient) error {
	c, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	proposal, _, err := p.Proposal("Probe", nil, nil)
	if err != nil {
		return err
	}
	tx, err := proposal.EndorseWithContext(c)
	if err != nil {
		return err
	}
	tx, _, err = p.SignTransaction(tx)
	if err != nil {
		return err
	}
	sent := time.Now()
	v.mu.Lock()
	for id, t := range v.attempts {
		if !sent.Before(t.Add(v.TimeLimit)) {
			delete(v.attempts, id)
		}
	}
	v.attempts[tx.TransactionID()] = sent
	v.mu.Unlock()
	v.emit("probe_sent", map[string]any{
		"txId":           tx.TransactionID(),
		"sentAt":         sent.UTC(),
		"deadline":       sent.Add(v.TimeLimit).UTC(),
		"sentMonoNs":     sent.Sub(v.started).Nanoseconds(),
		"deadlineMonoNs": sent.Add(v.TimeLimit).Sub(v.started).Nanoseconds(),
	})
	commit, err := tx.SubmitWithContext(c)
	if err != nil {
		return err
	}
	st, err := commit.StatusWithContext(c)
	if err != nil {
		return err
	}
	observed := time.Now()
	v.emit("probe_commit_observed", map[string]any{
		"txId":           tx.TransactionID(),
		"blockNumber":    st.BlockNumber,
		"validationCode": st.Code.String(),
		"observedAt":     observed.UTC(),
		"observedMonoNs": observed.Sub(v.started).Nanoseconds(),
	})
	return nil
}

func (v *Online) lease(ctx context.Context, tx pgx.Tx, h Point) (*ProbeEvidence, uint64, error) {
	v.mu.Lock()
	epoch, ready, reason := v.epoch, v.ready, v.hardError
	candidates := make(map[string]time.Time, len(v.attempts))
	ids := make([]string, 0, len(v.attempts))
	now := time.Now()
	for id, sent := range v.attempts {
		if now.Before(sent.Add(v.TimeLimit)) {
			candidates[id] = sent
			ids = append(ids, id)
		}
	}
	v.mu.Unlock()
	if reason != nil {
		return nil, epoch, errors.Join(ErrUnavailable, reason)
	}
	// With a saved checkpoint, a new process still needs an original unexpired probe.
	if !ready || len(ids) == 0 {
		return nil, epoch, ErrStale
	}
	_, m, _, err := v.Instance.Role(v.Role)
	if err != nil {
		return nil, epoch, err
	}
	rows, err := tx.Query(ctx, `SELECT tx_id, block_no, value FROM fabric_version
		WHERE deployment=$1 AND key=$2 AND block_no<=$3 AND tx_id=ANY($4)`, v.Deployment.DeploymentID, registry.ProbeKey(m), h.Number, ids)
	if err != nil {
		return nil, epoch, err
	}
	entries, err := pgx.CollectRows(rows, pgx.RowToStructByName[probeVersionRow])
	if err != nil {
		return nil, epoch, err
	}
	var best *ProbeEvidence
	for _, entry := range entries {
		var probe registry.Probe
		if err := json.Unmarshal(entry.Value, &probe); err != nil || probe.TxID != entry.TxID || probe.Identity != m {
			return nil, epoch, fmt.Errorf("invalid applied probe %s", entry.TxID)
		}
		sent := candidates[entry.TxID]
		deadline := sent.Add(v.TimeLimit)
		if best == nil || deadline.After(best.Deadline) {
			best = &ProbeEvidence{
				TxID:         entry.TxID,
				Identity:     m,
				ProbeBlock:   entry.BlockNo,
				View:         h,
				Sent:         sent,
				Deadline:     deadline,
				SentMono:     sent.Sub(v.started).Nanoseconds(),
				DeadlineMono: deadline.Sub(v.started).Nanoseconds(),
			}
		}
	}
	if best == nil {
		return nil, epoch, ErrStale
	}
	return best, epoch, nil
}

func (v *Online) checkLease(p *ProbeEvidence, epoch uint64, now time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.ready || v.epoch != epoch {
		return errors.Join(ErrUnavailable, v.hardError)
	}
	if p == nil || !now.Before(p.Deadline) {
		return ErrStale
	}
	p.Adopted, p.AdoptedMono = now, now.Sub(v.started).Nanoseconds()
	return nil
}

// SetStaticProbe configures an explicit original probe lease for deterministic testing when Online runtime is nil.
func (sp *StateProvider) SetStaticProbe(p *ProbeLease) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if p == nil {
		sp.staticProbe = nil
		return
	}
	cp := *p
	sp.staticProbe = &cp
}

// SetMonoClock overrides the monotonic clock helper used for probe deadline checks in deterministic tests.
func (sp *StateProvider) SetMonoClock(fn func() time.Time) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if fn == nil {
		sp.monoClock = time.Now
		return
	}
	sp.monoClock = fn
}

// IsProbeFresh enforces that an active original probe lease has not reached its monotonic clock deadline.
// When original is supplied, the check strictly binds to that original probe's immutable deadline rather than
// extending it with any newer probe observed by the runtime.
func (sp *StateProvider) IsProbeFresh(original ...ProbeLease) (ProbeLease, error) {
	sp.mu.RLock()
	clock := sp.monoClock
	rt := sp.runtime
	staticP := sp.staticProbe
	last := sp.lastProbe
	sp.mu.RUnlock()
	if clock == nil {
		clock = time.Now
	}
	nowMono := clock()
	probe := staticP
	if rt != nil {
		probe = last
	}
	if len(original) > 0 {
		probe = &original[0]
	} else if rt != nil && sp.db != nil && (probe == nil || !nowMono.Before(probe.Deadline)) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		view, err := sp.AssembleProtocolSnapshot(ctx, "", nowMono)
		if err != nil {
			return ProbeLease{}, err
		}
		l := view.Probe.Lease()
		probe = &l
	}
	if probe == nil || probe.TxID == "" || !nowMono.Before(probe.Deadline) {
		return ProbeLease{}, protocol.NewError(protocol.ErrCodeStateStale, "no unexpired original probe lease")
	}

	if rt != nil {
		rt.mu.Lock()
		ready, hard := rt.ready, rt.hardError
		sent, exists := rt.attempts[probe.TxID]
		rt.mu.Unlock()
		if !ready {
			msg := "online view not ready"
			if hard != nil {
				msg = hard.Error()
			}
			return ProbeLease{}, protocol.NewError(protocol.ErrCodeStateUnavailable, msg)
		}
		origDeadline := sent.Add(rt.TimeLimit)
		if !exists || !sent.Equal(probe.SentAt) || !origDeadline.Equal(probe.Deadline) {
			return ProbeLease{}, protocol.NewError(protocol.ErrCodeStateStale, "original probe is not from this runtime")
		}
		// Enforce monotonic deadline from the runtime's original sent time even if probe.Deadline lost its monotonic reading.
		if !nowMono.Before(origDeadline) {
			return ProbeLease{}, protocol.NewError(protocol.ErrCodeStateStale, "original probe monotonic deadline reached")
		}
	}
	if staticP != nil || rt != nil {
		checked := *probe
		checked.CheckedMonoNs = probe.SentMonoNs + nowMono.Sub(probe.SentAt).Nanoseconds()
		return checked, nil
	}
	return ProbeLease{}, protocol.NewError(protocol.ErrCodeStateStale, "no active original probe lease")
}
