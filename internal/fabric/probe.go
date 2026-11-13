package fabric

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	api "graduation-design/internal/fabricapi"

	"github.com/jackc/pgx/v5"
)

type probeEvidence struct {
	TxID         string         `json:"txId"`
	Identity     api.Management `json:"identity"`
	ProbeBlock   uint64         `json:"probeBlockNumber"`
	View         point          `json:"view"`
	Sent         time.Time      `json:"sentAt"`
	Deadline     time.Time      `json:"deadline"`
	Adopted      time.Time      `json:"adoptedAt"`
	SentMono     int64          `json:"sentMonoNs"`
	DeadlineMono int64          `json:"deadlineMonoNs"`
	AdoptedMono  int64          `json:"adoptedMonoNs"`
}

func (v *online) start(ctx context.Context) (func(), error) {
	reader, err := v.instance.peer("c", "read")
	if err != nil {
		return nil, err
	}
	sender, err := v.instance.peer("c", v.role)
	if err != nil {
		reader.close()
		return nil, err
	}
	v.started = time.Now()
	v.attempts = map[string]time.Time{}
	v.emit("probe_config", map[string]any{"interval": v.interval.String(), "lifetime": v.timeLimit.String(), "identity": sender.role, "monotonicOrigin": v.started.UTC()})
	c, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() { v.follow(c, reader) })
	wg.Go(func() { v.probeLoop(c, sender) })
	return func() { cancel(); wg.Wait(); sender.close(); reader.close() }, nil
}

func (v *online) probeLoop(ctx context.Context, p *peerClient) {
	ticker := time.NewTicker(v.interval)
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

func (v *online) sendProbe(ctx context.Context, p *peerClient) error {
	c, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	proposal, _, err := p.proposal("Probe", nil, nil)
	if err != nil {
		return err
	}
	tx, err := proposal.EndorseWithContext(c)
	if err != nil {
		return err
	}
	tx, _, err = p.signTransaction(tx)
	if err != nil {
		return err
	}
	sent := time.Now()
	v.mu.Lock()
	for id, t := range v.attempts {
		if !sent.Before(t.Add(v.timeLimit)) {
			delete(v.attempts, id)
		}
	}
	v.attempts[tx.TransactionID()] = sent
	v.mu.Unlock()
	v.emit("probe_sent", map[string]any{
		"txId": tx.TransactionID(), "sentAt": sent.UTC(), "deadline": sent.Add(v.timeLimit).UTC(),
		"sentMonoNs": sent.Sub(v.started).Nanoseconds(), "deadlineMonoNs": sent.Add(v.timeLimit).Sub(v.started).Nanoseconds(),
	})
	commit, err := tx.SubmitWithContext(c)
	if err != nil {
		return err
	}
	status, err := commit.StatusWithContext(c)
	if err != nil {
		return err
	}
	observed := time.Now()
	v.emit("probe_commit_observed", map[string]any{"txId": tx.TransactionID(), "blockNumber": status.BlockNumber,
		"validationCode": status.Code.String(), "observedAt": observed.UTC(), "observedMonoNs": observed.Sub(v.started).Nanoseconds()})
	return nil
}

func (v *online) lease(ctx context.Context, tx pgx.Tx, h point) (*probeEvidence, uint64, error) {
	v.mu.Lock()
	epoch, ready, reason := v.epoch, v.ready, v.hardError
	candidates := make(map[string]time.Time, len(v.attempts))
	ids := make([]string, 0, len(v.attempts))
	now := time.Now()
	for id, sent := range v.attempts {
		if now.Before(sent.Add(v.timeLimit)) {
			candidates[id] = sent
			ids = append(ids, id)
		}
	}
	v.mu.Unlock()
	if reason != nil {
		return nil, epoch, errors.Join(errUnavailable, reason)
	}
	// With a saved checkpoint, a new process still needs a usable probe.
	if !ready || len(ids) == 0 {
		return nil, epoch, errStale
	}
	_, m, _, err := v.instance.role(v.role)
	if err != nil {
		return nil, epoch, err
	}
	rows, err := tx.Query(ctx, `SELECT tx_id, block_no, value FROM fabric_version
		WHERE deployment=$1 AND key=$2 AND block_no<=$3 AND tx_id=ANY($4)`, v.d.DeploymentID, api.ProbeKey(m), h.Number, ids)
	if err != nil {
		return nil, epoch, err
	}
	defer rows.Close()
	var best *probeEvidence
	for rows.Next() {
		var id string
		var n uint64
		var raw []byte
		if err := rows.Scan(&id, &n, &raw); err != nil {
			return nil, epoch, err
		}
		var probe api.Probe
		if err := json.Unmarshal(raw, &probe); err != nil || probe.TxID != id || probe.Identity != m {
			return nil, epoch, fmt.Errorf("invalid applied probe %s", id)
		}
		sent, deadline := candidates[id], candidates[id].Add(v.timeLimit)
		if best == nil || deadline.After(best.Deadline) {
			best = &probeEvidence{TxID: id, Identity: m, ProbeBlock: n, View: h, Sent: sent, Deadline: deadline,
				SentMono: sent.Sub(v.started).Nanoseconds(), DeadlineMono: deadline.Sub(v.started).Nanoseconds()}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, epoch, err
	}
	if best == nil {
		return nil, epoch, errStale
	}
	return best, epoch, nil
}

func (v *online) checkLease(p *probeEvidence, epoch uint64, now time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.ready || v.epoch != epoch {
		return errors.Join(errUnavailable, v.hardError)
	}
	if p == nil || !now.Before(p.Deadline) {
		return errStale
	}
	p.Adopted, p.AdoptedMono = now, now.Sub(v.started).Nanoseconds()
	return nil
}
