package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	api "graduation-design/internal/fabricapi"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	gw "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func timedProposal(p *peerClient, method string, arg []byte, timestamp time.Time) (*pb.SignedProposal, error) {
	_, raw, err := p.proposal(method, arg, nil)
	if err != nil {
		return nil, err
	}
	w, err := decode(raw, &gw.ProposedTransaction{})
	if err != nil {
		return nil, err
	}
	proposal, err := decode(w.Proposal.ProposalBytes, &pb.Proposal{})
	if err != nil {
		return nil, err
	}
	h, err := decode(proposal.Header, &cb.Header{})
	if err != nil {
		return nil, err
	}
	ch, err := decode(h.ChannelHeader, &cb.ChannelHeader{})
	if err != nil {
		return nil, err
	}
	ch.Timestamp = timestamppb.New(timestamp)
	h.ChannelHeader, err = proto.Marshal(ch)
	if err != nil {
		return nil, err
	}
	proposal.Header, err = proto.Marshal(h)
	if err != nil {
		return nil, err
	}
	body, err := proto.Marshal(proposal)
	if err != nil {
		return nil, err
	}
	sig, err := p.signer(digestBytes(body))
	return &pb.SignedProposal{ProposalBytes: body, Signature: sig}, err
}

func (a acceptance) timestamps() error {
	g := a.cloneGrant("time-normal")
	if _, err := a.op("time-normal", "U", "RegisterGrant", g, "VALID"); err != nil {
		return err
	}
	g = a.cloneGrant("time-border")
	for _, org := range []string{"a", "b", "c"} {
		p, err := a.instance.peer(org, "U")
		if err != nil {
			return err
		}
		backfill := time.Now().Add(-12 * time.Second)
		proposal, err := timedProposal(p, "RegisterGrant", payload(g), backfill)
		if err != nil {
			p.close()
			return err
		}
		res, rpcErr := pb.NewEndorserClient(p.conn).ProcessProposal(a.ctx, proposal)
		p.close()
		message := res.GetResponse().GetMessage()
		a.log.event("backfilled_proposal", map[string]any{"peer": org, "proposalTime": backfill, "status": res.GetResponse().GetStatus(), "message": message, "rpcError": fmt.Sprint(rpcErr), "signedProposal": proposal})
		if rpcErr == nil && res.GetResponse().GetStatus() == 200 ||
			!strings.Contains(strings.ToLower(message+" "+fmt.Sprint(rpcErr)), "time") {
			return fmt.Errorf("peer %s did not enforce proposal time window: %s (%v)", org, message, rpcErr)
		}
	}
	p, err := a.instance.peer("c", "U")
	if err != nil {
		return err
	}
	defer p.close()
	t := time.Now().Truncate(time.Second)
	g.EXP = t.Add(api.PeerTimeWindow + api.ClockError).Unix()
	for _, test := range []struct {
		at   time.Time
		code int32
	}{{t, 500}, {t.Add(-time.Millisecond), 200}} {
		proposal, err := timedProposal(p, "RegisterGrant", payload(g), test.at)
		if err != nil {
			return err
		}
		res, err := pb.NewEndorserClient(p.conn).ProcessProposal(a.ctx, proposal)
		a.log.event("proposal_expiry_boundary", map[string]any{"proposalTime": test.at, "exp": g.EXP, "status": res.GetResponse().GetStatus(),
			"message": res.GetResponse().GetMessage(), "error": fmt.Sprint(err), "signedProposal": proposal})
		if err != nil || res.GetResponse().GetStatus() != test.code {
			return fmt.Errorf("time-margin boundary expected %d: %v %v", test.code, res.GetResponse(), err)
		}
	}
	root := a.f.G0
	root.ID, root.Digest, root.EXP = randomID(), randomID(), time.Now().Add(9*time.Second).Unix()
	root.Root = root.ID
	if _, err := a.op("short-parent", "C", "RegisterGrant", root, "VALID"); err != nil {
		return err
	}
	child := a.cloneGrant("delayed-child")
	child.Root, child.Parent, child.ParentDigest, child.EXP = root.ID, root.ID, root.Digest, root.EXP
	pending, err := a.prepared("delayed-child", "U", "RegisterGrant", child)
	if err != nil {
		return err
	}
	select {
	case <-a.ctx.Done():
		return a.ctx.Err()
	case <-time.After(time.Until(time.Unix(root.EXP, 0)) + 50*time.Millisecond):
	}
	result, err := a.finish(pending, "VALID")
	if err != nil {
		return err
	}
	deliveryAt := time.Now()
	canDeliver := root.Interval.Current(deliveryAt, 0) && child.Interval.Current(deliveryAt, 0)
	a.log.event("post_endorsement_expiry", map[string]any{"parentExp": root.EXP, "signedAt": pending.SignedAt, "commit": result.Commit,
		"deliveryCheckAt": deliveryAt, "timeEligible": canDeliver})
	if canDeliver {
		return fmt.Errorf("delayed child still inside the deadline")
	}
	_, err = a.op("revoke-expired", "C", "RevokeGrant", revokeOf(child), "VALID")
	return err
}

func (a acceptance) concurrency() error {
	g := a.cloneGrant("concurrent-key")
	key := a.id + "/concurrent-key"
	var concurrent [2]*operation
	var errs [2]error
	var wg sync.WaitGroup
	for n := range concurrent {
		wg.Go(func() { concurrent[n], errs[n] = a.j.prepare(a.ctx, key, "U", "RegisterGrant", payload(g)) })
	}
	wg.Wait()
	a.log.event("concurrent_acceptance", concurrent)
	if errs[0] != nil || errs[1] != nil || concurrent[0].TxID != concurrent[1].TxID ||
		!bytes.Equal(concurrent[0].Proposal, concurrent[1].Proposal) || !bytes.Equal(concurrent[0].Signed, concurrent[1].Signed) {
		return fmt.Errorf("concurrent acceptance did not return one signed transaction: %v", errs)
	}
	bad := g
	bad.Digest = randomID()
	_, err := a.j.prepare(a.ctx, key, "U", "RegisterGrant", payload(bad))
	a.log.event("operation_key_conflict", fmt.Sprint(err))
	if err == nil || !strings.Contains(err.Error(), "OPERATION_KEY_CONFLICT") {
		return fmt.Errorf("changed input reused the operation key")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	out, err := exec.CommandContext(a.ctx, exe, "operation", "--dir", a.instance.dir, "--key", key, "--timeout", "20s").CombinedOutput()
	if err != nil {
		return fmt.Errorf("separate process could not recover signed operation: %w: %s", err, out)
	}
	var result operation
	if err := json.Unmarshal(out, &result); err != nil {
		return err
	}
	a.log.event("separate_process_recovery", &result)
	if err := expectOperation(&result, "VALID"); err != nil {
		return err
	}
	if result.TxID != concurrent[0].TxID || !bytes.Equal(result.Signed, concurrent[0].Signed) {
		return fmt.Errorf("separate process submitted a different transaction")
	}
	retry, err := a.j.write(a.ctx, key, "U", "RegisterGrant", payload(g))
	if err != nil || retry.TxID != result.TxID || *retry.Commit != *result.Commit {
		return fmt.Errorf("confirmed exact retry differs from original: %v", err)
	}

	// Two proposals execute against the same active revision before either is submitted.
	revoke, err := a.prepared("race-revoke", "A1", "RevokeGrant", revokeOf(g))
	if err != nil {
		return err
	}
	replacement := a.cloneGrant("race-replacement")
	replace, err := a.prepared("race-replace", "U", "ReplaceGrant", api.Replacement{Old: revokeOf(g), New: replacement})
	if err != nil {
		return err
	}
	if _, err := a.finish(revoke, "VALID"); err != nil {
		return err
	}
	invalid, err := a.finish(replace, "MVCC_READ_CONFLICT")
	if err != nil {
		return err
	}
	if invalid.FailureCode == nil || *invalid.FailureCode != "STATE_CHANGED" {
		return fmt.Errorf("MVCC result did not map to STATE_CHANGED")
	}
	if err := a.absent("grant", replacement.ID); err != nil {
		return err
	}
	revoked, err := ledgerRecord[api.Grant](a.ctx, a.p, "grant", g.ID)
	if err != nil || revoked.Revision != 2 || revoked.Status != api.Revoked {
		return fmt.Errorf("revision race modified the grant more than once: %v", err)
	}

	one := a.cloneGrant("single-endorsement")
	op, err := a.prepared("single-endorsement", "U", "RegisterGrant", one, "AMsp")
	if err != nil {
		return err
	}
	invalid, err = a.finish(op, "ENDORSEMENT_POLICY_FAILURE")
	if err != nil {
		return err
	}
	if invalid.FailureCode == nil || *invalid.FailureCode != "COMMIT_INVALID" {
		return fmt.Errorf("invalid endorsement code was not mapped to COMMIT_INVALID")
	}
	if err := a.absent("grant", one.ID); err != nil {
		return err
	}
	if _, err := a.op("multi-endorsement", "U", "RegisterGrant", one, "VALID"); err != nil {
		return err
	}

	dep := a.cloneGrant("domain-dependency")
	waiting, err := a.prepared("domain-dependency", "U", "RegisterGrant", dep)
	if err != nil {
		return err
	}
	domain, err := ledgerRecord[api.Domain](a.ctx, a.p, "domain", "A")
	if err != nil {
		return err
	}
	m := api.DomainStatus{Bound: domain.Bound, ID: domain.ID, ExpectedRevision: domain.Revision, Status: api.Suspended}
	if _, err := a.op("suspend-domain", "T", "SetDomainStatus", m, "VALID"); err != nil {
		return err
	}
	m.ExpectedRevision++
	m.Status = api.Active
	resumed := false
	defer func() {
		if !resumed {
			_, err := a.op("resume-domain", "T", "SetDomainStatus", m, "VALID")
			if err != nil {
				a.log.event("domain_cleanup_error", err.Error())
			}
		}
	}()
	if _, err := a.finish(waiting, "MVCC_READ_CONFLICT"); err != nil {
		return err
	}
	if _, err := a.op("inactive-qualification", "U", "RegisterGrant", dep, "INVALID_STATE"); err != nil {
		return err
	}
	if err := a.absent("grant", dep.ID); err != nil {
		return err
	}
	if _, err := a.op("resume-domain", "T", "SetDomainStatus", m, "VALID"); err != nil {
		return err
	}
	resumed = true
	_, err = a.op("current-qualification", "U", "RegisterGrant", dep, "VALID")
	return err
}

func (a acceptance) invokeRetryDuringOutage(original *operation, grant api.Grant) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	originalInput := filepath.Join(a.dir, "invoke-retry-original.json")
	if err := os.WriteFile(originalInput, payload(grant), 0644); err != nil {
		return err
	}
	changedInput := filepath.Join(a.dir, "invoke-retry-changed.json")
	grant.Digest = randomID()
	if err := os.WriteFile(changedInput, payload(grant), 0644); err != nil {
		return err
	}
	invoke := func(input string) *exec.Cmd {
		return exec.CommandContext(a.ctx, exe, "invoke", "--dir", a.instance.dir, "--timeout", "10s",
			"--key", original.Key, "--role", original.Role, "--method", original.Method, "--input", input)
	}
	exact := invoke(originalInput)
	exactOutput, exactErr := exact.CombinedOutput()
	conflict := invoke(changedInput)
	conflictOutput, conflictErr := conflict.CombinedOutput()
	var retried operation
	decodeErr := json.Unmarshal(exactOutput, &retried)
	matchesOriginal := decodeErr == nil && bytes.Equal(payload(&retried), payload(original))
	a.log.event("peer_c_outage_invoke_retry", map[string]any{
		"operationKey": original.Key, "txId": original.TxID, "exactExitCode": exact.ProcessState.ExitCode(),
		"exactMatchesOriginal": matchesOriginal, "exactOutput": string(exactOutput),
		"changedExitCode": conflict.ProcessState.ExitCode(), "changedOutput": string(conflictOutput),
	})
	if exactErr != nil || !matchesOriginal {
		return fmt.Errorf("invoke exact retry did not return the original pending operation during C Peer outage: %v (decode: %v)", exactErr, decodeErr)
	}
	if conflict.ProcessState.ExitCode() != 1 || strings.TrimSpace(string(conflictOutput)) != "OPERATION_KEY_CONFLICT: "+original.Key {
		return fmt.Errorf("invoke changed-input retry did not report an operation key conflict during C Peer outage: %q (%v)", conflictOutput, conflictErr)
	}
	stored, err := a.j.load(a.ctx, original.Key, a.j.db)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload(stored), payload(original)) {
		return fmt.Errorf("invoke retry changed the stored pending operation during C Peer outage")
	}
	return nil
}

func (a acceptance) replay() error {
	g := a.cloneGrant("lost-response")
	before, err := a.prepared("lost-response", "U", "RegisterGrant", g)
	if err != nil {
		return err
	}
	pending, err := a.j.recover(a.ctx, before.Key, func(ctx context.Context, tx *client.Transaction) error {
		if _, err := tx.SubmitWithContext(ctx); err != nil {
			return err
		}
		return status.Error(codes.Unavailable, "injected loss of the original broadcast response")
	})
	a.log.event("lost_submit_response", pending)
	if err != nil {
		return err
	}
	if err := expectOperation(pending, "PENDING"); err != nil {
		return err
	}
	if before.TxID != pending.TxID || !bytes.Equal(before.Signed, pending.Signed) || pending.BroadcastAt == nil ||
		!strings.Contains(pending.Observation, "injected loss") {
		return fmt.Errorf("lost response did not retain the original pending operation")
	}
	p, err := a.instance.peer("c", "U")
	if err != nil {
		return err
	}
	defer p.close()
	seen, err := p.commitStatus(a.ctx, pending.TxID)
	if err != nil || seen.Result != pb.TxValidationCode_VALID {
		return fmt.Errorf("could not observe original VALID: %v %v", seen, err)
	}
	tx, err := p.gateway.NewTransaction(pending.Signed)
	if err != nil {
		return err
	}
	var replay *outcome
	findReplay := func() (bool, error) {
		h, err := p.height(a.ctx)
		if err != nil {
			return false, err
		}
		for n := seen.BlockNumber + 1; n < h; n++ {
			b, err := p.getBlock(a.ctx, n)
			if err != nil {
				return false, err
			}
			for _, t := range b.Transactions {
				if t.ID == pending.TxID && t.Code == pb.TxValidationCode_DUPLICATE_TXID {
					replay = &outcome{point: b.point, Index: t.Index, Code: t.Code.String()}
					return true, nil
				}
			}
		}
		return false, nil
	}
	if _, err := tx.SubmitWithContext(a.ctx); err != nil {
		a.log.event("replay_sorter_response", err.Error())
		if !strings.Contains(err.Error(), "request already processed") {
			return fmt.Errorf("replay original signed bytes: %w", err)
		}
		// SmartBFT can suppress a recent replay before it reaches Peer validation.
		// Reset the in-memory ordering request pool while retaining the ledgers.
		out, err := a.instance.run(a.ctx, "compose", "restart", "orderer-a", "orderer-b", "orderer-c", "orderer-d")
		a.log.event("restart_orderers_before_replay", string(out))
		if err != nil {
			return err
		}
		err = poll(a.ctx, 20*time.Second, func() (bool, error) {
			// A replay can reach the Peer while its submit response is unavailable.
			if found, err := findReplay(); found || err != nil {
				return found, err
			}
			c, cancel := context.WithTimeout(a.ctx, 4*time.Second)
			defer cancel()
			_, err := tx.SubmitWithContext(c)
			if err != nil {
				a.log.event("replay_sorter_response", err.Error())
			}
			return err == nil || strings.Contains(fmt.Sprint(err), "request already exists"), nil
		})
		if err != nil {
			return fmt.Errorf("could not observe replay submission or commit after sorter restart: %w", err)
		}
	}
	if replay == nil {
		if err := poll(a.ctx, 12*time.Second, findReplay); err != nil {
			return fmt.Errorf("no DUPLICATE_TXID evidence: %w", err)
		}
	}
	a.log.event("duplicate_txid", map[string]any{"txId": pending.TxID, "originalBlock": seen.BlockNumber, "replay": replay, "signedSha256": api.Digest(pending.Signed)})
	final, err := a.finish(pending, "VALID")
	if err != nil || final.Commit.Number != seen.BlockNumber || final.TxID != pending.TxID ||
		!bytes.Equal(final.Signed, pending.Signed) || !final.BroadcastAt.Equal(*pending.BroadcastAt) {
		return fmt.Errorf("replay replaced the original outcome: %v", err)
	}
	return nil
}
