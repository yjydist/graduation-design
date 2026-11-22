package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"grad/platform/gateway"
	"grad/platform/policy"
	"grad/protocol"
)

func postJSON(handler http.Handler, path string, input any) (*httptest.ResponseRecorder, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp, nil
}

func (e *e1Trial) ensureTaskContextNormal(handler http.Handler, taskID string, now int64) (int64, error) {
	var version int64
	if err := e.db.QueryRow(e.ctx, `SELECT COALESCE(MAX(context_version),0) FROM trusted_contexts WHERE deployment_id=$1 AND task_id=$2`, e.d.DeploymentID, taskID).Scan(&version); err != nil {
		return 0, err
	}
	resp, err := postJSON(handler, "/v1/contexts/"+taskID, gateway.ContextUpdateRequest{
		ExpectedContextVersion: version,
		SourceID:               "ctx-verifier-c",
		ObservedAt:             now - 1,
		RiskLevel:              policy.RiskNormal,
		AccessDeadline:         e.f.RPTask.EXP,
	})
	if err != nil {
		return 0, err
	}
	if resp.Code != http.StatusOK {
		return 0, fmt.Errorf("context update returned HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var out gateway.ContextResponse
	err = json.Unmarshal(resp.Body.Bytes(), &out)
	return out.ContextVersion, err
}

func (e *e1Trial) buildLeafExecutePackage(handler http.Handler, req protocol.AccessRequest, spec protocol.TaskSpec,
	priv *ecdsa.PrivateKey, keyID, presentation string, anc []protocol.AncestorCredential, grants []string,
	paths []protocol.TrustPathEntry, now int64) (protocol.AccessEvidencePackage, gateway.ChallengeResponse, error) {
	var challenge gateway.ChallengeResponse
	hash, err := req.Hash(false)
	if err != nil {
		return protocol.AccessEvidencePackage{}, challenge, err
	}
	resp, err := postJSON(handler, "/v1/auth/challenges", gateway.ChallengeRequest{Actor: req.Actor, TaskID: req.TaskID, RequestHash: hash})
	if err != nil {
		return protocol.AccessEvidencePackage{}, challenge, err
	}
	if resp.Code != http.StatusCreated {
		return protocol.AccessEvidencePackage{}, challenge, fmt.Errorf("challenge returned HTTP %d: %s", resp.Code, resp.Body.String())
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &challenge); err != nil {
		return protocol.AccessEvidencePackage{}, challenge, err
	}
	pkg := protocol.AccessEvidencePackage{Request: req, TaskSpec: spec, ChallengeID: challenge.ChallengeID, AncestorCredentials: anc, Grants: grants, TrustPaths: paths}
	_, _, err = protocol.AssembleAccessEvidencePackage(&pkg, presentation, keyID, priv, protocol.ChallengeContext{
		ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, Audience: challenge.Audience, IssuedAt: challenge.IssuedAt, ExpiresAt: challenge.ExpiresAt,
	}, now, false)
	return pkg, challenge, err
}

func gatewayPostExecute(handler http.Handler, pkg protocol.AccessEvidencePackage) *httptest.ResponseRecorder {
	resp, err := postJSON(handler, "/v1/access/execute", pkg)
	if err != nil {
		resp = httptest.NewRecorder()
		http.Error(resp, err.Error(), http.StatusBadRequest)
	}
	return resp
}
