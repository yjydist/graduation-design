package gateway

import (
	"context"
	"strings"

	"grad/protocol"
)

// ChallengeRequest models a challenge issuance request bound to actor, taskId, and requestHash.
type ChallengeRequest struct {
	Actor       string `json:"actor"`
	TaskID      string `json:"taskId"`
	RequestHash string `json:"requestHash"`
}

// ChallengeResponse models a newly issued short-lived access challenge.
type ChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	Audience    string `json:"audience"`
	IssuedAt    int64  `json:"issuedAt"`
	ExpiresAt   int64  `json:"expiresAt"`
}

// CreateChallenge validates the request, mints a fresh cryptographic nonce and short-lived
// challenge row bound to actor, taskId, requestHash, and audience, and persists it.
func (s *Service) CreateChallenge(ctx context.Context, req ChallengeRequest) (*ChallengeResponse, error) {
	if strings.TrimSpace(req.Actor) == "" || strings.TrimSpace(req.TaskID) == "" || !hex64Re.MatchString(req.RequestHash) {
		return nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "actor, taskId, and lowercase 64-hex requestHash are required")
	}

	nonce, err := protocol.GenerateNonce()
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "generate challenge nonce", err)
	}
	issuedAt := s.now().Unix()
	expiresAt := issuedAt + ChallengeTTLSeconds
	challengeID := "urn:grad:challenge:" + newUUID()

	if _, err := s.cfg.DB.Exec(ctx, `INSERT INTO challenges(
		deployment_id, challenge_id, nonce, actor, task_id, request_hash, audience, issued_at, expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		s.cfg.DeploymentID, challengeID, nonce, req.Actor, req.TaskID, req.RequestHash, s.cfg.Audience, issuedAt, expiresAt,
	); err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "insert challenge", err)
	}

	return &ChallengeResponse{
		ChallengeID: challengeID,
		Nonce:       nonce,
		Audience:    s.cfg.Audience,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
	}, nil
}
