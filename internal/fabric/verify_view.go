package fabric

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (a acceptance) viewFaults() error {
	copy := *a.d
	copy.DeploymentID = "injected-view-" + a.id
	v := view{db: a.v.db, d: &copy}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, name := range []string{"fabric_version", "fabric_current", "fabric_block", "fabric_head"} {
			if _, err := v.db.Exec(ctx, "DELETE FROM "+name+" WHERE deployment=$1", copy.DeploymentID); err != nil {
				a.log.event("isolated_view_cleanup_error", err.Error())
			}
		}
	}()
	var blocks []*block
	for n := uint64(0); n < 4; n++ {
		b, err := a.p.getBlock(a.ctx, n)
		if err != nil {
			return err
		}
		blocks = append(blocks, b)
	}
	if err := v.apply(a.ctx, blocks[0], nil); err != nil {
		return err
	}
	rejected := func(label string, err error) error {
		a.log.event("view_injection", map[string]any{"case": label, "error": fmt.Sprint(err)})
		if err == nil {
			return fmt.Errorf("view accepted %s", label)
		}
		return nil
	}
	if err := rejected("missing-block", v.apply(a.ctx, blocks[2], nil)); err != nil {
		return err
	}
	if err := rejected("candidate-rollback", checkSourceHeight(1, &blocks[1].point)); err != nil {
		return err
	}
	corrupt, err := a.observedRaw(1)
	if err != nil {
		return err
	}
	corrupt.Header.DataHash[0] ^= 1
	_, err = parseBlock(corrupt)
	if err := rejected("wrong-data-hash", err); err != nil {
		return err
	}
	corrupt, err = a.observedRaw(1)
	if err != nil {
		return err
	}
	corrupt.Metadata.Metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER] = nil
	_, err = parseBlock(corrupt)
	if err := rejected("missing-validation-filter", err); err != nil {
		return err
	}
	injected := *blocks[1]
	key := "injected-key"
	write := func(value string) []*kvrwset.KVWrite { return []*kvrwset.KVWrite{{Key: key, Value: []byte(value)}} }
	injected.Transactions = []blockTx{
		{ID: "first", Index: 0, Code: pb.TxValidationCode_VALID, Writes: write("one")},
		{ID: "invalid", Index: 1, Code: pb.TxValidationCode_MVCC_READ_CONFLICT, Writes: write("wrong")},
		{ID: "last", Index: 2, Code: pb.TxValidationCode_VALID, Writes: write("two")},
	}
	stop := errors.New("injected interruption before checkpoint commit")
	if err := v.apply(a.ctx, &injected, func() error { return stop }); !errors.Is(err, stop) {
		return fmt.Errorf("atomicity injection did not interrupt application: %v", err)
	}
	h, err := v.head(a.ctx, v.db, false)
	if err != nil || h == nil || h.Number != 0 {
		return fmt.Errorf("interruption changed checkpoint: %v %v", h, err)
	}
	countVersions := func() (int, error) {
		var n int
		err := v.db.QueryRow(a.ctx, "SELECT count(*) FROM fabric_version WHERE deployment=$1 AND key=$2", copy.DeploymentID, key).Scan(&n)
		return n, err
	}
	if n, err := countVersions(); n != 0 || err != nil {
		return fmt.Errorf("interruption exposed uncommitted versions: %d %v", n, err)
	}
	for range 2 {
		if err := v.apply(a.ctx, &injected, nil); err != nil {
			return err
		}
	}
	var value []byte
	err = v.db.QueryRow(a.ctx, "SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2", copy.DeploymentID, key).Scan(&value)
	n, countErr := countVersions()
	if err != nil || string(value) != "two" || n != 2 || countErr != nil {
		return fmt.Errorf("same-block ordering, invalid filtering or idempotence failed: %q %d %v %v", value, n, err, countErr)
	}
	changed, err := a.observedRaw(1)
	if err != nil {
		return err
	}
	changed.Metadata.Metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER][0] = byte(pb.TxValidationCode_DUPLICATE_TXID)
	bad, err := parseBlock(changed)
	if err != nil {
		return err
	}
	if err := rejected("same-height-conflict", v.apply(a.ctx, bad, nil)); err != nil {
		return err
	}
	deleted := *blocks[2]
	deleted.Transactions = []blockTx{{Index: 0, ID: "delete", Writes: []*kvrwset.KVWrite{{Key: key, IsDelete: true}}}}
	if err := v.apply(a.ctx, &deleted, nil); err != nil {
		return err
	}
	var nCurrent int
	err = v.db.QueryRow(a.ctx, "SELECT count(*) FROM fabric_current WHERE deployment=$1 AND key=$2", copy.DeploymentID, key).Scan(&nCurrent)
	if err != nil || nCurrent != 0 {
		return fmt.Errorf("deleted key remains current: %d %v", nCurrent, err)
	}
	err = v.db.QueryRow(a.ctx, "SELECT value FROM fabric_version WHERE deployment=$1 AND key=$2 ORDER BY block_no DESC,tx_index DESC LIMIT 1", copy.DeploymentID, key).Scan(&value)
	if err != nil || value != nil {
		return fmt.Errorf("missing historical deletion marker: %q %v", value, err)
	}
	next := *blocks[3]
	next.ConfigDigest = randomID()
	if err := rejected("changed-config", v.apply(a.ctx, &next, nil)); err != nil {
		return err
	}
	next = *blocks[3]
	next.Transactions = slices.Clone(next.Transactions)
	next.Transactions[0].DefinitionChange = true
	if err := rejected("changed-definition", v.apply(a.ctx, &next, nil)); err != nil {
		return err
	}
	if err := v.apply(a.ctx, blocks[3], nil); err != nil {
		return err
	}
	if _, err := v.db.Exec(a.ctx, "DELETE FROM fabric_block WHERE deployment=$1 AND block_no=3", copy.DeploymentID); err != nil {
		return err
	}
	tx, err := v.db.Begin(a.ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	end := blocks[3].point
	return rejected("historical-gap", v.historicalPoint(a.ctx, tx, &end, end))
}

func (a acceptance) waitApplied(blockNo uint64) error {
	return poll(a.ctx, 8*time.Second, func() (bool, error) {
		head, err := a.v.head(a.ctx, a.v.db, false)
		return head != nil && head.Number >= blockNo, err
	})
}

func (a acceptance) applyThrough(height uint64) error {
	last, err := a.v.head(a.ctx, a.v.db, false)
	if err != nil {
		return err
	}
	start := uint64(0)
	if last != nil {
		start = last.Number + 1
	}
	for n := start; n <= height; n++ {
		b, err := a.p.getBlock(a.ctx, n)
		if err != nil {
			return err
		}
		if err := a.v.apply(a.ctx, b, nil); err != nil {
			return err
		}
		a.log.event("block_applied", b.point)
	}
	return nil
}

func (a acceptance) snapshotAndProbes() error {
	if err := a.interleavedSnapshot(); err != nil {
		return err
	}
	return a.probeLimits()
}

func (a acceptance) interleavedSnapshot() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	startCtx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(startCtx, rt, a.f.G1.ID)
	cancel()
	if err != nil {
		return err
	}
	g := a.cloneGrant("snapshot")
	created, err := a.op("snapshot-grant", "U", "RegisterGrant", g, "VALID")
	if err != nil {
		return err
	}
	if err := a.instance.awaitEndorsers(a.ctx, *created.Commit); err != nil {
		return err
	}
	if err := a.waitApplied(created.Commit.Number); err != nil {
		return err
	}
	var revoked *operation
	old, err := a.v.snapshot(a.ctx, g.ID, nil, rt, func() error {
		op, err := a.op("snapshot-revoke", "A1", "RevokeGrant", revokeOf(g), "VALID")
		revoked = op
		if err != nil {
			return err
		}
		return a.waitApplied(revoked.Commit.Number)
	})
	if err != nil || old.Grants[0].Status != api.Active || old.Number >= revoked.Commit.Number {
		return fmt.Errorf("interleaved read did not preserve pre-revocation snapshot: %v", err)
	}
	latest, err := a.v.snapshot(a.ctx, g.ID, nil, rt, nil)
	if err != nil || latest.Number < revoked.Commit.Number || latest.Grants[0].Status != api.Revoked {
		return fmt.Errorf("next online snapshot did not adopt the revocation: %v", err)
	}
	for _, h := range []struct {
		number uint64
		status string
	}{{old.Number, api.Active}, {revoked.Commit.Number, api.Revoked}} {
		s, err := a.v.snapshot(a.ctx, g.ID, &h.number, nil, nil)
		if err != nil || s.Grants[0].Status != h.status || s.Probe != nil {
			return fmt.Errorf("historical state at %d expected %s: %v", h.number, h.status, err)
		}
		a.log.event("historical", s)
	}
	a.log.event("interleaved_snapshots", map[string]any{"h": old, "r": revoked.Commit, "next": latest})
	_, err = a.v.snapshot(a.ctx, randomID(), nil, rt, nil)
	a.log.event("missing_dependency", fmt.Sprint(err))
	if err == nil || !strings.Contains(err.Error(), "MISSING_DEPENDENCY") {
		return fmt.Errorf("missing dependency yielded usable snapshot: %v", err)
	}
	return nil
}

func (a acceptance) probeLimits() error {
	if _, err := a.op("ordinary-probe", "C", "Probe", nil, "UNAUTHORIZED"); err != nil {
		return err
	}
	if _, err := a.op("probe-other-key", "probe2", "Probe", "other", "INVALID_STRUCTURE"); err != nil {
		return err
	}
	if _, err := a.op("probe-business-write", "probe2", "RegisterGrant", a.cloneGrant("probe-business-write"), "UNAUTHORIZED"); err != nil {
		return err
	}
	rt := newRuntime(a)
	rt.role = "probe2"
	rt.started = time.Now()
	rt.attempts = map[string]time.Time{}
	rt.resume()
	checkStale := func(label string) error {
		_, err := a.v.snapshot(a.ctx, a.f.G1.ID, nil, rt, nil)
		a.log.event("probe_rejection", map[string]any{"case": label, "error": fmt.Sprint(err)})
		if !errors.Is(err, errStale) {
			return fmt.Errorf("%s should be stale: %v", label, err)
		}
		return nil
	}
	if err := checkStale("new-process-no-original-probe"); err != nil {
		return err
	}
	invalid, err := a.prepared("invalid-probe", "probe2", "Probe", nil, "AMsp")
	if err != nil {
		return err
	}
	rt.attempts[invalid.TxID] = time.Now()
	invalid, err = a.finish(invalid, "ENDORSEMENT_POLICY_FAILURE")
	if err != nil {
		return err
	}
	if err := a.applyThrough(invalid.Commit.Number); err != nil {
		return err
	}
	if err := checkStale("invalid-probe-even-after-application"); err != nil {
		return err
	}

	send := func(label string) (*operation, error) {
		op, err := a.prepared(label, "probe2", "Probe", nil)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		rt.attempts[op.TxID] = now
		a.log.event("manual_probe_sent", map[string]any{"txId": op.TxID, "sentMonoNs": now.Sub(rt.started).Nanoseconds(),
			"deadlineMonoNs": now.Add(rt.timeLimit).Sub(rt.started).Nanoseconds(), "label": label})
		return a.finish(op, "VALID")
	}
	valid, err := send("valid-probe")
	if err != nil {
		return err
	}
	if err := checkStale("valid-commit-before-block-application"); err != nil {
		return err
	}
	b, err := a.p.getBlock(a.ctx, valid.Commit.Number)
	if err != nil {
		return err
	}
	writes := b.Transactions[valid.Commit.Index].Writes
	_, role, _, err := a.instance.role("probe2")
	if err != nil || len(writes) != 1 || writes[0].Key != api.ProbeKey(role) {
		return fmt.Errorf("probe write set is not confined to its own identity")
	}
	if err := a.applyThrough(b.Number); err != nil {
		return err
	}
	s, err := a.v.snapshot(a.ctx, a.f.G1.ID, nil, rt, nil)
	if err != nil || s.Probe.TxID != valid.TxID || s.Probe.ProbeBlock != valid.Commit.Number {
		return fmt.Errorf("valid applied probe was not adopted: %v", err)
	}
	if err := rt.checkLease(s.Probe, rt.epoch, s.Probe.Deadline); !errors.Is(err, errStale) {
		return fmt.Errorf("deadline equality allowed the original probe")
	}
	if err := a.v.apply(a.ctx, b, nil); err != nil {
		return err
	}
	repeated, err := a.v.snapshot(a.ctx, a.f.G1.ID, nil, rt, nil)
	if err != nil || repeated.Probe.TxID != s.Probe.TxID || !repeated.Probe.Deadline.Equal(s.Probe.Deadline) {
		return fmt.Errorf("repeat delivery changed the deadline: %v", err)
	}
	a.log.event("replayed_probe_original_deadline", repeated.Probe)
	late, err := send("late-apply-probe")
	if err != nil {
		return err
	}
	select {
	case <-a.ctx.Done():
		return a.ctx.Err()
	case <-time.After(time.Until(rt.attempts[late.TxID].Add(rt.timeLimit)) + 30*time.Millisecond):
	}
	if err := a.applyThrough(late.Commit.Number); err != nil {
		return err
	}
	return checkStale("probe-applied-after-original-deadline")
}

func (a acceptance) waitProbe(rt *online, after time.Time, max time.Duration) (*snapshot, error) {
	var got *snapshot
	err := poll(a.ctx, max, func() (bool, error) {
		s, err := a.v.snapshot(a.ctx, a.f.G1.ID, nil, rt, nil)
		if errors.Is(err, errUnavailable) || errors.Is(err, errStale) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if s.Probe.Sent.After(after) {
			got = s
			return true, nil
		}
		return false, nil
	})
	return got, err
}

func (a acceptance) sharedViewResume() error {
	address, err := a.instance.port("FABRIC_PEER_C")
	if err != nil {
		return err
	}
	var peerHeight uint64
	var advanced *outcome
	// Hold the first height response while another consumer applies a real probe block.
	advanceAfterHeight := func(ctx context.Context, method string, req, reply any, conn *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if err := invoke(ctx, method, req, reply, conn, opts...); err != nil || peerHeight != 0 {
			return err
		}
		response := reply.(*pb.ProposalResponse).GetResponse()
		info, err := decode(response.GetPayload(), &cb.BlockchainInfo{})
		if err != nil || response.GetStatus() != 200 || info.GetHeight() == 0 {
			return fmt.Errorf("could not observe Peer height before advancing the shared view")
		}
		peerHeight = info.GetHeight()
		probe, err := a.op("shared-view-probe", "probe2", "Probe", nil, "VALID")
		if err != nil {
			return err
		}
		if probe.Commit.Number < peerHeight {
			return fmt.Errorf("probe block %d did not advance Peer height %d", probe.Commit.Number, peerHeight)
		}
		if err := a.applyThrough(probe.Commit.Number); err != nil {
			return err
		}
		advanced = probe.Commit
		a.log.event("shared_view_advanced", map[string]any{"peerHeightBefore": peerHeight, "checkpoint": advanced, "txId": probe.TxID})
		return nil
	}
	conn, err := dialTLS(address, "peer-c", a.instance.peerTLS("c"), grpc.WithUnaryInterceptor(advanceAfterHeight))
	if err != nil {
		return err
	}
	defer conn.Close()
	reader := *a.p
	reader.conn = conn
	ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
	defer cancel()
	rt := newRuntime(a)
	replayed := false
	rt.observe = func(event string, details any) {
		a.log.event(event, details)
		if p, ok := details.(point); event == "block_applied" && ok && advanced != nil && p == advanced.point {
			replayed = true
			cancel()
		}
	}
	if err := rt.followOnce(ctx, &reader); !replayed || !errors.Is(err, context.Canceled) {
		return fmt.Errorf("could not resume after shared checkpoint advanced: %w", err)
	}
	a.log.event("shared_view_resumed", advanced.point)
	return nil
}

func (a acceptance) checkpointQueryOutage() error {
	last, err := a.v.head(a.ctx, a.v.db, false)
	if err != nil || last == nil || last.Number == 0 {
		return fmt.Errorf("no saved checkpoint after genesis: %v", err)
	}
	address, err := a.instance.port("FABRIC_PEER_C")
	if err != nil {
		return err
	}
	// Let height, genesis and deployment validation succeed before failing
	// only the query for the saved checkpoint.
	height := strconv.FormatUint(last.Number, 10)
	var injected codes.Code
	intercept := func(ctx context.Context, method string, req, reply any, conn *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if method == pb.Endorser_ProcessProposal_FullMethodName {
			p, err := decode(req.(*pb.SignedProposal).GetProposalBytes(), &pb.Proposal{})
			if err != nil {
				return err
			}
			payload, err := decode(p.Payload, &pb.ChaincodeProposalPayload{})
			if err != nil {
				return err
			}
			spec, err := decode(payload.Input, &pb.ChaincodeInvocationSpec{})
			if err != nil {
				return err
			}
			args := spec.GetChaincodeSpec().GetInput().GetArgs()
			if spec.GetChaincodeSpec().GetChaincodeId().GetName() == "qscc" && len(args) == 3 &&
				string(args[0]) == "GetBlockByNumber" && string(args[2]) == height {
				return status.Error(injected, "injected checkpoint query failure")
			}
		}
		return invoke(ctx, method, req, reply, conn, opts...)
	}
	conn, err := dialTLS(address, "peer-c", a.instance.peerTLS("c"), grpc.WithUnaryInterceptor(intercept))
	if err != nil {
		return err
	}
	defer conn.Close()
	reader := *a.p
	reader.conn = conn
	rt := newRuntime(a)
	for _, test := range []struct {
		code codes.Code
		want error
	}{
		{codes.Unavailable, errStale},
		{codes.DeadlineExceeded, errStale},
		{codes.NotFound, errUnavailable},
	} {
		injected = test.code
		ctx, cancel := context.WithTimeout(a.ctx, 8*time.Second)
		fetchErr := rt.followOnce(ctx, &reader)
		cancel()
		if status.Code(fetchErr) != test.code {
			return fmt.Errorf("expected checkpoint query %s, got %v", test.code, fetchErr)
		}
		_, err := a.v.snapshot(a.ctx, a.f.G1.ID, nil, rt, nil)
		a.log.event("checkpoint_query_rejected", map[string]any{"checkpoint": last, "rpcError": fetchErr.Error(), "onlineError": fmt.Sprint(err)})
		if !errors.Is(err, test.want) {
			return fmt.Errorf("checkpoint query %s: expected %w, got %v", test.code, test.want, err)
		}
	}
	h, err := a.v.head(a.ctx, a.v.db, false)
	if err != nil || h == nil || *h != *last {
		return fmt.Errorf("checkpoint changed while its source was unavailable: %v %v", h, err)
	}
	recovery := time.Now()
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	fresh, err := a.waitProbe(rt, recovery, 15*time.Second)
	if err != nil || fresh.Number <= last.Number {
		return fmt.Errorf("checkpoint query recovery did not adopt a new probe: %v", err)
	}
	a.log.event("checkpoint_query_recovered", fresh.Probe)
	return nil
}

func (a acceptance) expectStaleCheck(event string, last *point, timeout time.Duration) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	check := exec.CommandContext(a.ctx, exe, "check", "--dir", a.instance.dir, "--grant", a.f.G1.ID, "--timeout", timeout.String())
	out, err := check.CombinedOutput()
	exitCode := check.ProcessState.ExitCode()
	a.log.event(event, map[string]any{"checkpoint": last, "exitCode": exitCode, "output": string(out)})
	if exitCode != 1 || !bytes.HasPrefix(out, []byte("STATE_STALE:")) || bytes.Contains(out, []byte("DEPLOYMENT_MISMATCH")) {
		return fmt.Errorf("%s: expected STATE_STALE, got exit %d: %q (%v)", event, exitCode, out, err)
	}
	return nil
}

func (a acceptance) networkFaults() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, err := a.instance.run(ctx, "start", "orderer-c", "orderer-d", "peer-c")
		if err != nil {
			a.log.event("fault_cleanup_error", err.Error())
		}
	}()
	if _, err := a.waitProbe(rt, time.Time{}, 12*time.Second); err != nil {
		return err
	}
	fault := func(action string, services ...string) (time.Time, error) {
		out, err := a.instance.run(a.ctx, append([]string{action}, services...)...)
		now := time.Now()
		a.log.event("docker_fault", map[string]any{"action": action, "services": services, "time": now, "output": string(out)})
		return now, err
	}
	one, err := fault("stop", "orderer-d")
	if err != nil {
		return err
	}
	fresh, err := a.waitProbe(rt, one, 24*time.Second)
	if err != nil {
		return fmt.Errorf("one stopped sorter prevented new valid probes: %w", err)
	}
	a.log.event("one_orderer_stopped", fresh)
	two, err := fault("stop", "orderer-c")
	if err != nil {
		return err
	}
	// Let any block already ordered before the second stop reach the trusted Peer.
	select {
	case <-a.ctx.Done():
		return a.ctx.Err()
	case <-time.After(2 * time.Second):
	}
	still, err := a.p.height(a.ctx)
	if err != nil {
		return err
	}
	g := a.cloneGrant("two-orderer-pending")
	pending, err := a.prepared("two-orderer-pending", "U", "RegisterGrant", g)
	if err != nil {
		return err
	}
	after, err := a.finish(pending, "PENDING")
	if err != nil || after.TxID != pending.TxID || !bytes.Equal(after.Signed, pending.Signed) {
		return fmt.Errorf("expected unknown commit with preserved original transaction: %v", err)
	}
	if err := poll(a.ctx, api.ProbeLifetime+2*time.Second, func() (bool, error) {
		_, err := a.v.snapshot(a.ctx, a.f.G1.ID, nil, rt, nil)
		return errors.Is(err, errStale), nil
	}); err != nil {
		return fmt.Errorf("two stopped sorters did not expire the local view: %w", err)
	}
	stopped, err := a.p.height(a.ctx)
	if err != nil || stopped != still {
		return fmt.Errorf("expected no new confirmations with two orderers stopped: %d -> %d %v", still, stopped, err)
	}
	h := still - 1
	historical, err := a.v.snapshot(a.ctx, a.f.G1.ID, &h, nil, nil)
	if err != nil {
		return err
	}
	a.log.event("two_orderers_stopped", map[string]any{"faultAt": two, "initialHeight": still, "finalHeight": stopped,
		"online": "STATE_STALE", "historical": historical, "operation": after})
	restored, err := fault("start", "orderer-c", "orderer-d")
	if err != nil {
		return err
	}
	fresh, err = a.waitProbe(rt, restored, 40*time.Second)
	if err != nil {
		return fmt.Errorf("ordering recovery did not adopt a new probe: %w", err)
	}
	a.log.event("orderers_recovered", fresh)

	peerDown, err := fault("stop", "peer-c")
	if err != nil {
		return err
	}
	if err := a.invokeRetryDuringOutage(after, g); err != nil {
		return err
	}
	other, err := a.instance.peer("a", "probe2")
	if err != nil {
		return err
	}
	defer other.close()
	proposal, _, err := other.proposal("Probe", nil, []string{"AMsp", "BMsp"})
	if err != nil {
		return err
	}
	ready, err := proposal.EndorseWithContext(a.ctx)
	if err != nil {
		return err
	}
	commit, err := ready.SubmitWithContext(a.ctx)
	if err != nil {
		return err
	}
	observed, err := commit.StatusWithContext(a.ctx)
	if err != nil || !observed.Successful {
		return fmt.Errorf("A and B did not confirm a probe during C peer outage: %v", err)
	}
	if err := poll(a.ctx, api.ProbeLifetime+3*time.Second, func() (bool, error) {
		_, err := a.v.snapshot(a.ctx, a.f.G1.ID, nil, rt, nil)
		return errors.Is(err, errStale), nil
	}); err != nil {
		return fmt.Errorf("C peer outage did not expire its view: %w", err)
	}
	last, err := a.v.head(a.ctx, a.v.db, false)
	if err != nil || last == nil || last.Number >= observed.BlockNumber {
		return fmt.Errorf("view adopted a block during C peer outage: %v %v", last, err)
	}
	a.log.event("peer_c_outage", map[string]any{"faultAt": peerDown, "lastApplied": last, "externalProbeTxId": proposal.TransactionID(),
		"peerACommitBlock": observed.BlockNumber, "validationCode": observed.Code.String(), "online": "STATE_STALE"})
	if err := a.expectStaleCheck("peer_c_outage_new_check", last, 2*time.Second); err != nil {
		return err
	}
	peerUp, err := fault("start", "peer-c")
	if err != nil {
		return err
	}
	fresh, err = a.waitProbe(rt, peerUp, 30*time.Second)
	if err != nil || fresh.Number < observed.BlockNumber {
		return fmt.Errorf("C peer recovery did not catch up and adopt a new probe: %v", err)
	}
	a.log.event("peer_c_recovered", fresh)
	recovered, err := a.finish(after, "VALID")
	if err != nil {
		return err
	}
	if recovered.TxID != after.TxID || !bytes.Equal(recovered.Proposal, after.Proposal) || !bytes.Equal(recovered.Signed, after.Signed) {
		return fmt.Errorf("network recovery changed the original pending transaction")
	}
	return nil
}

func (a acceptance) chaincodeOutage() error {
	last, err := a.v.head(a.ctx, a.v.db, false)
	if err != nil || last == nil {
		return fmt.Errorf("no checkpoint before C chaincode outage: %v", err)
	}
	if _, err := a.instance.run(a.ctx, "compose", "--profile", "registry", "stop", "cc-c"); err != nil {
		return err
	}
	restored := false
	defer func() {
		if !restored {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if _, err := a.instance.run(ctx, "compose", "--profile", "registry", "start", "cc-c"); err != nil {
				a.log.event("fault_cleanup_error", err.Error())
			}
		}
	}()
	height, err := a.p.height(a.ctx)
	if err != nil || height <= last.Number {
		return fmt.Errorf("C Peer must still serve the checkpoint during the chaincode outage: height %d, %v", height, err)
	}
	a.log.event("chaincode_c_outage", map[string]any{"peerHeight": height, "checkpoint": last})
	rt := newRuntime(a)
	rt.role = "probe2"
	interrupted := make(chan struct{}, 1)
	rt.observe = func(event string, details any) {
		a.log.event(event, details)
		if event == "delivery_interrupted" {
			select {
			case interrupted <- struct{}{}:
			default:
			}
		}
	}
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	if err := a.expectStaleCheck("chaincode_c_outage_new_check", last, 8*time.Second); err != nil {
		return err
	}
	select {
	case <-interrupted:
	case <-a.ctx.Done():
		return a.ctx.Err()
	case <-time.After(5 * time.Second):
		return fmt.Errorf("did not observe a failed deployment query during the C chaincode outage")
	}
	if _, err := a.instance.run(a.ctx, "compose", "--profile", "registry", "start", "cc-c"); err != nil {
		return err
	}
	restored = true
	fresh, err := a.waitProbe(rt, time.Now(), 30*time.Second)
	if err != nil {
		return fmt.Errorf("running reader did not adopt a new probe after C chaincode recovery: %w", err)
	}
	a.log.event("chaincode_c_recovered", fresh)
	return nil
}

func (a acceptance) restart() error {
	h, err := a.v.head(a.ctx, a.v.db, false)
	if err != nil || h == nil {
		return fmt.Errorf("no applied checkpoint before restart: %v", err)
	}
	before, err := a.v.snapshot(a.ctx, a.f.G1.ID, &h.Number, nil, nil)
	if err != nil {
		return err
	}
	volumes := func() ([]byte, error) {
		return exec.CommandContext(a.ctx, "docker", "volume", "ls", "--filter", "label=com.docker.compose.project="+a.instance.env["COMPOSE_PROJECT_NAME"], "--format", "{{.Name}}").Output()
	}
	list, err := volumes()
	if err != nil || len(bytes.Fields(list)) < 8 {
		return fmt.Errorf("expected persisted Compose data volumes: %v", err)
	}
	down, err := a.instance.run(a.ctx, "down")
	a.log.event("restart_down", string(down))
	if err != nil {
		return err
	}
	listDown, err := volumes()
	if err != nil || !bytes.Equal(list, listDown) {
		return fmt.Errorf("default down did not preserve data volumes: %v", err)
	}
	up, err := a.instance.run(a.ctx, "up")
	a.log.event("restart_up", string(up))
	if err != nil {
		return err
	}
	if err := a.d.validatePeer(a.ctx, a.p); err != nil {
		return err
	}
	after, err := a.v.head(a.ctx, a.v.db, false)
	if err != nil || after == nil || *after != *h {
		return fmt.Errorf("checkpoint changed across normal restart: %v -> %v (%v)", h, after, err)
	}
	history, err := a.v.snapshot(a.ctx, a.f.G1.ID, &h.Number, nil, nil)
	if err != nil || !bytes.Equal(payload(history), payload(before)) {
		return fmt.Errorf("history changed across normal restart: %v", err)
	}
	a.log.event("restart_preserved", map[string]any{"deploymentId": a.d.DeploymentID, "checkpoint": after, "volumes": strings.Fields(string(listDown))})
	rt := newRuntime(a)
	restartTime := time.Now()
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	fresh, err := a.waitProbe(rt, restartTime, 45*time.Second)
	if err != nil {
		return err
	}
	a.log.event("restart_new_probe", fresh)
	return nil
}
