package gateway

import (
	"net/http"
	"strings"

	"grad/platform/internal/httpx"
	"grad/protocol"
)

// ChallengeRequest models POST /v1/auth/challenges.
type ChallengeRequest struct {
	Actor       string `json:"actor"`
	TaskID      string `json:"taskId"`
	RequestHash string `json:"requestHash"`
}

// ChallengeResponse models 201 Created from POST /v1/auth/challenges.
type ChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	Audience    string `json:"audience"`
	IssuedAt    int64  `json:"issuedAt"`
	ExpiresAt   int64  `json:"expiresAt"`
}

func (s *Server) handleCreateChallenge(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONBody(r, MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	var req ChallengeRequest
	if err := protocol.DecodeStrictJSON(body, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	if strings.TrimSpace(req.Actor) == "" || strings.TrimSpace(req.TaskID) == "" || !hex64Re.MatchString(req.RequestHash) {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "actor, taskId, and lowercase 64-hex requestHash are required")
		return
	}

	nonce, err := protocol.GenerateNonce()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
		return
	}
	issuedAt := s.now().Unix()
	expiresAt := issuedAt + ChallengeTTLSeconds
	challengeID := "urn:grad:challenge:" + newUUID()

	if _, err := s.cfg.DB.Exec(r.Context(), `INSERT INTO challenges(
		deployment_id, challenge_id, nonce, actor, task_id, request_hash, audience, issued_at, expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		s.cfg.DeploymentID, challengeID, nonce, req.Actor, req.TaskID, req.RequestHash, s.cfg.Audience, issuedAt, expiresAt,
	); err != nil {
		writeError(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, ChallengeResponse{
		ChallengeID: challengeID,
		Nonce:       nonce,
		Audience:    s.cfg.Audience,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
	})
}
