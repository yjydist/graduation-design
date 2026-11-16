package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

// verifyRecoveryHTTP sends the proof bundle through the real authenticated
// management boundary, then resumes the original signed transaction after restart.
func (a acceptance) verifyRecoveryHTTP(bundle *protocol.RecoveryDualProofBundle) (map[string]any, error) {
	svc, err := newFabricManagementService(a.j.db, a.instance, a.d)
	if err != nil {
		return nil, err
	}
	ready, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	backend := svc.backend.(*journalOperationBackend)
	backend.beforeBroadcast = func(ctx context.Context, key string) {
		select {
		case ready <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	server, err := a.managementHTTPServer(svc)
	if err != nil {
		return nil, err
	}
	defer server.Close()
	client, err := a.managementHTTPClient(server, "registrarB")
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	request := func(c *http.Client, method, path, key string, payload any) (int, []byte, error) {
		var body io.Reader
		if payload != nil {
			raw, err := json.Marshal(payload)
			if err != nil {
				return 0, nil, err
			}
			body = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(a.ctx, method, server.URL+path, body)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		return resp.StatusCode, raw, err
	}
	const endpoint = "/v1/management/RecoverIdentity"
	rejected := map[string]int{}
	for _, name := range []string{"raw-mutation", "missing-application", "missing-management", "changed-subject"} {
		copy := *bundle
		var payload any = &copy
		switch name {
		case "raw-mutation":
			payload = recoveryMutation(bundle.Challenge)
		case "missing-application":
			copy.NewAppJWSSignature = ""
		case "missing-management":
			copy.NewManagementSignatureDER = ""
		case "changed-subject":
			copy.Challenge.SubjectID += "-tampered"
		}
		key := a.id + "/recovery-reject/" + name
		code, _, err := request(client, http.MethodPost, endpoint, key, payload)
		if err != nil || code != http.StatusForbidden {
			return nil, fmt.Errorf("recovery %s: HTTP %d: %v", name, code, err)
		}
		var count int
		if err := a.j.db.QueryRow(a.ctx, `SELECT COUNT(*) FROM operations WHERE deployment_id=$1 AND operation_key=$2`, a.d.DeploymentID, key).Scan(&count); err != nil || count != 0 {
			return nil, fmt.Errorf("rejected recovery queued: count=%d: %v", count, err)
		}
		rejected[name] = code
	}
	key := a.id + "/recovery-http"
	code, raw, err := request(client, http.MethodPost, endpoint, key, bundle)
	var accepted OperationView
	if err != nil || code != http.StatusAccepted {
		return nil, fmt.Errorf("recovery admission: HTTP %d: %s: %v", code, raw, err)
	}
	if err := json.Unmarshal(raw, &accepted); err != nil {
		return nil, err
	}
	select {
	case <-ready:
	case <-a.ctx.Done():
		return nil, a.ctx.Err()
	}
	original, err := backend.journal.load(a.ctx, key, a.j.db)
	if err != nil || original == nil || len(original.Signed) == 0 {
		return nil, fmt.Errorf("recovery original not durably signed: %v", err)
	}
	queryPath := "/v1/operations/" + accepted.OperationID
	code, raw, err = request(client, http.MethodGet, queryPath, "", nil)
	var pending OperationView
	if err != nil || code != 200 || json.Unmarshal(raw, &pending) != nil || pending.Status != "PENDING" {
		return nil, fmt.Errorf("owner pending query: HTTP %d: %s: %v", code, raw, err)
	}
	_, auditorB, _, err := a.instance.role("domainB")
	if err != nil {
		return nil, err
	}
	_, auditorA, _, err := a.instance.role("domainA")
	if err != nil {
		return nil, err
	}
	svc.SetOperationAuditors([]api.Management{auditorB, auditorA})
	queryCodes := map[string]int{"owner": code}
	for _, check := range []struct {
		role string
		want int
	}{{"registrarA", 403}, {"wrongB", 403}, {"domainA", 403}, {"domainB", 200}} {
		other, err := a.managementHTTPClient(server, check.role)
		if err != nil {
			return nil, err
		}
		code, raw, err := request(other, http.MethodGet, queryPath, "", nil)
		other.CloseIdleConnections()
		if err != nil || code != check.want {
			return nil, fmt.Errorf("operation query %s: HTTP %d: %s: %v", check.role, code, raw, err)
		}
		queryCodes[check.role] = code
	}
	// A new host recovers the original signed bytes while the first host is paused.
	restarted, err := newFabricManagementService(a.j.db, a.instance, a.d)
	if err != nil {
		return nil, err
	}
	if err := restarted.ResumePending(a.ctx); err != nil {
		return nil, err
	}
	result, err := restarted.GetOperation(a.ctx, accepted.OperationID)
	if err != nil || result.Status != "CONFIRMED" || result.ValidationCode == nil || *result.ValidationCode != "VALID" || result.TxID != original.TxID {
		return nil, fmt.Errorf("recovery original commit: %+v: %v", result, err)
	}
	// The original server's query observes the same committed operation.
	code, raw, err = request(client, http.MethodGet, queryPath, "", nil)
	var queried OperationView
	if err != nil || code != 200 || json.Unmarshal(raw, &queried) != nil || queried.TxID != result.TxID || queried.Status != "CONFIRMED" {
		return nil, fmt.Errorf("owner confirmed query: HTTP %d: %s: %v", code, raw, err)
	}
	code, raw, err = request(client, http.MethodPost, endpoint, key, bundle)
	var retry OperationView
	if err != nil || code != 202 || json.Unmarshal(raw, &retry) != nil || retry.OperationID != result.OperationID || retry.TxID != original.TxID {
		return nil, fmt.Errorf("recovery exact retry: HTTP %d: %s: %v", code, raw, err)
	}
	code, raw, err = request(client, http.MethodPost, endpoint, key+"-replay", bundle)
	var replay struct {
		ErrorCode string `json:"errorCode"`
	}
	if err != nil || (code != 403 && code != 409) || json.Unmarshal(raw, &replay) != nil ||
		(replay.ErrorCode != protocol.ErrCodeChallengeReplay && replay.ErrorCode != protocol.ErrCodeStateChanged && replay.ErrorCode != protocol.ErrCodeRecoveryProofInvalid) {
		return nil, fmt.Errorf("recovery replay: HTTP %d: %s: %v", code, raw, err)
	}
	var replayCount int
	if err := a.j.db.QueryRow(a.ctx, `SELECT COUNT(*) FROM operations WHERE deployment_id=$1 AND operation_key=$2`, a.d.DeploymentID, key+"-replay").Scan(&replayCount); err != nil || replayCount != 0 {
		return nil, fmt.Errorf("replay produced a new operation: %d: %v", replayCount, err)
	}
	var consumed bool
	if err := a.j.db.QueryRow(a.ctx, `SELECT consumed FROM recovery_challenges WHERE deployment_id=$1 AND challenge_id=$2 AND consumed_by_operation_id=$3`, a.d.DeploymentID, bundle.Challenge.ChallengeID, accepted.OperationID).Scan(&consumed); err != nil || !consumed {
		return nil, fmt.Errorf("recovery consumption binding: %v", err)
	}
	report := map[string]any{"rejected": rejected, "queryStatus": queryCodes, "pending": pending, "confirmed": result, "sameOriginalTxId": result.TxID == original.TxID, "replayStatus": code, "replayErrorCode": replay.ErrorCode, "replayQueuedOperations": replayCount, "challengeConsumed": consumed}
	a.log.event("recovery_http_dual_proof_and_query_authorization", report)
	return report, nil
}
