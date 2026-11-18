package fabric

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"
)

// verifyManagementHTTPTransactions exercises real REST admission, endorsements, original
// commits, MVCC failure and restart recovery instead of injecting final results.
func (a acceptance) verifyManagementHTTPTransactions(grant api.Grant) (map[string]any, error) {
	currentGrant, err := ledgerRecord[api.Grant](a.ctx, a.p, "grant", grant.ID)
	if err != nil {
		return nil, err
	}
	grant = currentGrant
	svc, err := newFabricManagementService(a.j.db, a.instance, a.d)
	if err != nil {
		return nil, err
	}
	backend := svc.backend.(*journalOperationBackend)
	ready := make(chan string, 8)
	release := make(chan struct{})
	backend.beforeBroadcast = func(ctx context.Context, key string) {
		select {
		case ready <- key:
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
	client, err := a.managementHTTPClient(server, "U")
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	request := func(method, path, key string, value any) (int, OperationView, error) {
		var v OperationView
		var body io.Reader
		if value != nil {
			raw, err := json.Marshal(value)
			if err != nil {
				return 0, v, err
			}
			body = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(a.ctx, method, server.URL+path, body)
		if err != nil {
			return 0, v, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := client.Do(req)
		if err != nil {
			return 0, v, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, v, err
		}
		if resp.StatusCode < 300 {
			err = json.Unmarshal(raw, &v)
		}
		return resp.StatusCode, v, err
	}
	key1, key2 := a.id+"/http-mvcc-1", a.id+"/http-mvcc-2"
	mutation := api.Mutation{Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: grant.ID, ExpectedRevision: grant.Revision, ExpectedDigest: grant.Digest}
	// Stale preflight has no proposal and no durable admitted operation.
	stale := mutation
	stale.ExpectedRevision++
	code, _, err := request(http.MethodPost, "/v1/management/SuspendGrant", a.id+"/http-stale", stale)
	if err != nil || code != 409 {
		return nil, fmt.Errorf("management preflight: %d %v", code, err)
	}
	for _, key := range []string{key1, key2} {
		code, _, err = request(http.MethodPost, "/v1/management/SuspendGrant", key, mutation)
		if err != nil || code != 202 {
			return nil, fmt.Errorf("management accept: %d %v", code, err)
		}
	}
	for range 2 {
		select {
		case <-ready:
		case <-a.ctx.Done():
			return nil, a.ctx.Err()
		}
	}
	_, pending, err := request(http.MethodGet, "/v1/operations/"+a.d.DeploymentID+":"+key1, "", nil)
	if err != nil || pending.Status != "PENDING" {
		return nil, fmt.Errorf("expected original pending operation: %+v %v", pending, err)
	}
	close(release)
	wait := func(key string) (OperationView, error) {
		var out OperationView
		err := poll(a.ctx, 15*time.Second, func() (bool, error) {
			code, v, e := request(http.MethodGet, "/v1/operations/"+a.d.DeploymentID+":"+key, "", nil)
			out = v
			return e == nil && code == 200 && v.Status != "PENDING", e
		})
		return out, err
	}
	one, err := wait(key1)
	if err != nil {
		return nil, err
	}
	two, err := wait(key2)
	if err != nil {
		return nil, err
	}
	winner, loser := one, two
	if one.Status == "FAILED" {
		winner, loser = two, one
	}
	if winner.Status != "CONFIRMED" || winner.ValidationCode == nil || *winner.ValidationCode != "VALID" || loser.Status != "FAILED" || loser.ValidationCode == nil || *loser.ValidationCode != "MVCC_READ_CONFLICT" || loser.ErrorCode == nil || *loser.ErrorCode != "STATE_CHANGED" {
		return nil, fmt.Errorf("real HTTP MVCC outcomes: %+v %+v", one, two)
	}
	code, retry, err := request(http.MethodPost, "/v1/management/SuspendGrant", key1, mutation)
	if err != nil || code != 202 || retry.TxID != one.TxID {
		return nil, fmt.Errorf("exact retry replaced original transaction: %+v %v", retry, err)
	}
	// Resume the same grant via HTTP, then emulate a crash after original signing.
	current, err := ledgerRecord[api.Grant](a.ctx, a.p, "grant", grant.ID)
	if err != nil {
		return nil, err
	}
	resume := api.Mutation{Bound: mutation.Bound, ID: current.ID, ExpectedRevision: current.Revision, ExpectedDigest: current.Digest}
	key3 := a.id + "/http-resume"
	code, _, err = request(http.MethodPost, "/v1/management/ResumeGrant", key3, resume)
	if err != nil || code != 202 {
		return nil, fmt.Errorf("resume accept: %d %v", code, err)
	}
	if result, err := wait(key3); err != nil || result.Status != "CONFIRMED" {
		return nil, fmt.Errorf("resume result: %+v %v", result, err)
	}
	current, err = ledgerRecord[api.Grant](a.ctx, a.p, "grant", grant.ID)
	if err != nil {
		return nil, err
	}
	mutation.ExpectedRevision = current.Revision
	raw, _ := json.Marshal(mutation)
	_, caller, _, err := a.instance.role("U")
	if err != nil {
		return nil, err
	}
	key4 := a.id + "/http-restart"
	code, view, err := svc.Accept(a.ctx, key4, caller, "SuspendGrant", raw, false)
	if err != nil || code != 202 {
		return nil, err
	}
	original, err := backend.journal.prepare(a.ctx, key4, "U", "SuspendGrant", raw)
	if err != nil || original == nil || len(original.Signed) == 0 {
		return nil, fmt.Errorf("prepare recovery original: %v", err)
	}
	restarted, err := newFabricManagementService(a.j.db, a.instance, a.d)
	if err != nil {
		return nil, err
	}
	if err = restarted.ResumePending(a.ctx); err != nil {
		return nil, err
	}
	recovered, err := restarted.GetOperation(a.ctx, view.OperationID)
	if err != nil || recovered.Status != "CONFIRMED" || recovered.TxID != original.TxID {
		return nil, fmt.Errorf("restart replaced/lost original: %+v %v", recovered, err)
	}
	if strings.HasPrefix(recovered.TxID, "pending:") {
		return nil, fmt.Errorf("placeholder txID survived actual commit")
	}
	result := map[string]any{"confirmed": winner, "mvccConflict": loser, "pending": pending, "recovered": recovered, "sameOriginalTxId": original.TxID == recovered.TxID, "preflightStatus": 409}
	a.log.event("management_http_original_transactions", result)
	return result, nil
}

func (a acceptance) managementHTTPRecovery() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	if _, err = a.waitProbe(rt, time.Time{}, 12*time.Second); err != nil {
		return err
	}
	sp := NewStateProvider(a.j.db, a.d, rt)
	chain, err := a.provisionEphemeralRPChain(rt, sp, "http-"+a.id[:8], 500000, false, time.Now().UTC())
	if err != nil {
		return err
	}
	result, err := a.verifyManagementHTTPTransactions(chain.G1)
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(a.dir, "management-http.json"), result)
}

// managementHTTPServer mounts the actual handler behind verified domain mTLS.
func (a acceptance) managementHTTPServer(svc *ManagementOperationService) (*httptest.Server, error) {
	roots := x509.NewCertPool()
	for _, org := range []string{"a", "b", "c", "t"} {
		paths, err := filepath.Glob(filepath.Join(a.instance.orgDir(org), "msp", "cacerts", "*.pem"))
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			if !roots.AppendCertsFromPEM(raw) {
				return nil, fmt.Errorf("invalid management CA")
			}
		}
	}
	server := httptest.NewUnstartedServer(svc.Handler())
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	return server, nil
}

func (a acceptance) managementHTTPClient(server *httptest.Server, role string) (*http.Client, error) {
	certDER, key, _, err := a.loadRoleCertAndKey(role)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return nil, err
	}
	tr := server.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}, nil
}
