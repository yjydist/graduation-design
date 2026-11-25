package gateway

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"grad/platform/core/dao"
	"grad/platform/core/ledger"
	"grad/protocol"
	"grad/protocol/registry"
)

// IdentityEvidence records one verified identity node in a workbench decision proof.
type IdentityEvidence struct {
	DID               string `json:"did"`
	DomainID          string `json:"domainId,omitempty"`
	IssuerDID         string `json:"issuerDid,omitempty"`
	Kind              string `json:"kind"`
	Status            string `json:"status"`
	KeyVersion        uint64 `json:"keyVersion"`
	CertificationID   string `json:"certificationId,omitempty"`
	CertificationHash string `json:"certificationDigest,omitempty"`
	DecisionID        string `json:"decisionId"`
}

// DisclosureEvidence records minimal SD-JWT disclosure metadata for workbench display.
type DisclosureEvidence struct {
	SubjectDID        string            `json:"subjectDid"`
	IssuerDID         string            `json:"issuerDid"`
	CredentialID      string            `json:"credentialId"`
	SubjectKeyVersion uint64            `json:"subjectKeyVersion"`
	IssuerKeyVersion  uint64            `json:"issuerKeyVersion"`
	Disclosed         map[string]string `json:"disclosed"`
	Status            string            `json:"status"`
	DecisionID        string            `json:"decisionId"`
}

// DelegationEvidence records one delegation hop in a workbench decision proof.
type DelegationEvidence struct {
	GrantID        string `json:"grantId"`
	ParentID       string `json:"parentId,omitempty"`
	RootID         string `json:"rootId"`
	Mode           string `json:"mode"`
	IssuerDID      string `json:"issuerDid"`
	GranteeDID     string `json:"granteeDid"`
	Status         string `json:"status"`
	Revision       uint64 `json:"revision"`
	MaxAmountMinor int64  `json:"maxAmountMinor,omitempty"`
	RemainingDepth int64  `json:"remainingDepth"`
	NBF            int64  `json:"nbf"`
	EXP            int64  `json:"exp"`
	DecisionID     string `json:"decisionId,omitempty"`
}

// DecisionSummary projects shareable decision metadata for workbench views.
type DecisionSummary struct {
	DecisionID     string  `json:"decisionId,omitempty"`
	RequestID      string  `json:"requestId,omitempty"`
	ProbeTxID      string  `json:"probeTxId,omitempty"`
	Action         string  `json:"action"`
	Outcome        string  `json:"outcome"`
	Code           string  `json:"code"`
	QuoteID        *string `json:"quoteId,omitempty"`
	OrderID        *string `json:"orderId,omitempty"`
	FailedObjectID *string `json:"failedObjectId,omitempty"`
	BlockNumber    int64   `json:"blockNumber"`
	BlockHash      string  `json:"blockHash"`
	PolicyDigest   string  `json:"policyDigest"`
	ContextVersion int64   `json:"contextVersion"`
	ProbeDeadline  int64   `json:"probeDeadline"`
	DecisionAt     int64   `json:"decisionAt"`
}

// DecisionProof aggregates identity, disclosure, and delegation evidence for a decision.
type DecisionProof struct {
	Identity    []IdentityEvidence   `json:"identity"`
	Disclosures []DisclosureEvidence `json:"disclosures"`
	Delegations []DelegationEvidence `json:"delegations"`
}

// TaskEvidence aggregates shareable task-scoped decision, quote, and order evidence.
type TaskEvidence struct {
	DecisionProof
	Decisions []DecisionSummary `json:"decisions"`
	Quotes    []QuotePayload    `json:"quotes"`
	Orders    []OrderPayload    `json:"orders"`
}

func recordWorkbenchProof(ctx context.Context, tx dao.Tx, pre *precheckResult, decision string) error {
	snap := pre.view.Snapshot
	verified := pre.verified
	proof := DecisionProof{
		Identity: []IdentityEvidence{{DID: snap.Root.DID, Kind: "ROOT", Status: registry.Active,
			KeyVersion: snap.Root.KeyVersion, DecisionID: decision}},
	}
	seen := make(map[string]bool)
	addIdentity := func(did, issuer string) {
		if seen[did] {
			return
		}
		id, ok := snap.Identities[did]
		if !ok {
			return
		}
		seen[did] = true
		cert := snap.Certifications[snap.Domains[id.Domain].Certification]
		proof.Identity = append(proof.Identity, IdentityEvidence{
			DID: did, IssuerDID: issuer, DomainID: id.Domain, Kind: id.Kind, Status: id.Status, KeyVersion: id.KeyVersion,
			CertificationID: cert.ID, CertificationHash: cert.Digest, DecisionID: decision,
		})
	}
	addCredential := func(cred *protocol.VerifiedIdentityCredential) {
		claims := cred.Claims
		issuer := snap.Identities[claims.Issuer]
		addIdentity(snap.Domains[issuer.Domain].DID, snap.Root.DID)
		addIdentity(claims.Issuer, snap.Domains[issuer.Domain].DID)
		addIdentity(claims.Sub, claims.Issuer)
		attrs := make(map[string]string, 2)
		for _, key := range []string{"domain", "role"} {
			if value, ok := cred.Disclosed[key]; ok {
				attrs[key] = value
			}
		}
		proof.Disclosures = append(proof.Disclosures, DisclosureEvidence{
			SubjectDID: claims.Sub, IssuerDID: claims.Issuer, CredentialID: claims.ID,
			SubjectKeyVersion: claims.AppKeyVersion, IssuerKeyVersion: claims.IssuerKeyVersion,
			Disclosed: attrs, Status: snap.Credentials[claims.ID].Status, DecisionID: decision,
		})
	}
	addCredential(verified.LeafCredential)
	credentialIDs := make([]string, 0, len(verified.AncestorCreds))
	for id := range verified.AncestorCreds {
		credentialIDs = append(credentialIDs, id)
	}
	slices.Sort(credentialIDs)
	for _, id := range credentialIDs {
		addCredential(verified.AncestorCreds[id])
	}
	for _, hop := range verified.Grants {
		claims := hop.Claims
		item := DelegationFromAnchor(snap.Grants[claims.ID])
		item.MaxAmountMinor, item.DecisionID = claims.MaxAmountMinor, decision
		proof.Delegations = append(proof.Delegations, item)
	}
	_, err := tx.Exec(ctx, `INSERT INTO workbench_decision_proof(deployment_id,decision_id,body) VALUES($1,$2,$3)`,
		pre.pkg.Request.DeploymentID, decision, proof)
	return err
}

// DelegationFromAnchor converts an on-chain Grant anchor into a DelegationEvidence summary.
func DelegationFromAnchor(g registry.Grant) DelegationEvidence {
	return DelegationEvidence{GrantID: g.ID, ParentID: g.Parent, RootID: g.Root, Mode: g.Mode, IssuerDID: g.Issuer,
		GranteeDID: g.Grantee, Status: g.Status, Revision: g.Revision, RemainingDepth: int64(g.Depth), NBF: g.NBF, EXP: g.EXP}
}

// ReadDecision returns the original decision only to its request actor or a verified auditor.
// When the decision does not exist or is outside scope, it returns an error matching ErrDecisionNotFound.
func (s *Service) ReadDecision(ctx context.Context, id, actor string, auditor bool) (*DecisionRecord, error) {
	rows, err := s.cfg.DB.Query(ctx, `SELECT `+selectDecisionColumns+` FROM decisions
		WHERE deployment_id=$1 AND decision_id=$2 AND (actor=$3 OR $4)`, s.cfg.DeploymentID, id, actor, auditor)
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "query scoped decision", err)
	}
	rec, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[DecisionRecord])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "decision not found", ErrDecisionNotFound)
	}
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "scan scoped decision", err)
	}
	return &rec, nil
}

// ReadTaskEvidence returns shareable fields for one caller and task inside a consistent
// REPEATABLE READ read-only transaction.
func (s *Service) ReadTaskEvidence(ctx context.Context, actor, taskID string) (*TaskEvidence, error) {
	out := &TaskEvidence{
		DecisionProof: DecisionProof{Identity: []IdentityEvidence{}, Disclosures: []DisclosureEvidence{}, Delegations: []DelegationEvidence{}},
		Decisions:     []DecisionSummary{}, Quotes: []QuotePayload{}, Orders: []OrderPayload{},
	}
	err := dao.RunRepeatableReadTx(ctx, s.cfg.DB, func(tx dao.Tx) error {
		rows, err := tx.Query(ctx, `SELECT decision_id,action,outcome,code,quote_id,order_id,failed_object_id,
			COALESCE(block_number,0),COALESCE(block_hash,''),policy_digest,context_version,COALESCE(probe_deadline,0),decision_at
			FROM decisions WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 ORDER BY decision_at,decision_id`, s.cfg.DeploymentID, actor, taskID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var item DecisionSummary
			if err := rows.Scan(&item.DecisionID, &item.Action, &item.Outcome, &item.Code, &item.QuoteID, &item.OrderID, &item.FailedObjectID,
				&item.BlockNumber, &item.BlockHash, &item.PolicyDigest, &item.ContextVersion, &item.ProbeDeadline, &item.DecisionAt); err != nil {
				rows.Close()
				return err
			}
			out.Decisions = append(out.Decisions, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, item := range out.Decisions {
			var proof DecisionProof
			err := tx.QueryRow(ctx, `SELECT body FROM workbench_decision_proof WHERE deployment_id=$1 AND decision_id=$2`,
				s.cfg.DeploymentID, item.DecisionID).Scan(&proof)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			out.Identity = append(out.Identity, proof.Identity...)
			out.Disclosures = append(out.Disclosures, proof.Disclosures...)
			out.Delegations = append(out.Delegations, proof.Delegations...)
		}
		rows, err = tx.Query(ctx, `SELECT body FROM workbench_gateway_rejections
			WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 ORDER BY observed_at,request_id`, s.cfg.DeploymentID, actor, taskID)
		if err != nil {
			return err
		}
		rejections, err := pgx.CollectRows(rows, pgx.RowTo[DecisionSummary])
		if err != nil {
			return err
		}
		out.Decisions = append(out.Decisions, rejections...)
		slices.SortStableFunc(out.Decisions, func(a, b DecisionSummary) int {
			if a.DecisionAt < b.DecisionAt {
				return -1
			}
			if a.DecisionAt > b.DecisionAt {
				return 1
			}
			return 0
		})
		rows, err = tx.Query(ctx, `SELECT quote_id,task_id,actor,supplier_id,product_id,quantity,currency,unit_price_minor,total_amount_minor,issued_at,valid_until
			FROM quotes WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 ORDER BY issued_at,quote_id`, s.cfg.DeploymentID, actor, taskID)
		if err != nil {
			return err
		}
		out.Quotes, err = pgx.CollectRows(rows, pgx.RowToStructByName[QuotePayload])
		if err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT order_id,quote_id,task_id,actor,supplier_id,product_id,quantity,currency,total_amount_minor,idempotency_key,status,created_at
			FROM orders WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 ORDER BY created_at,order_id`, s.cfg.DeploymentID, actor, taskID)
		if err != nil {
			return err
		}
		out.Orders, err = pgx.CollectRows(rows, pgx.RowToStructByName[OrderPayload])
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// recordInactiveRejection records an actual precheck rejection without
// consuming the challenge or assigning a business decision ID.
func (s *Service) recordInactiveRejection(ctx context.Context, pkg *protocol.AccessEvidencePackage, view *ledger.StateSnapshot, leaf, requestID string, now time.Time, err error) error {
	code := protocol.CodeOf(err)
	if code != protocol.ErrCodeAncestorInactive && code != protocol.ErrCodeGrantInactive {
		return nil
	}
	if view == nil || view.Snapshot == nil || view.StateSource != ledger.SourceFabric {
		return nil
	}
	var failed *string
	for current := leaf; current != ""; {
		anchor, known := view.Snapshot.Grants[current]
		if !known {
			break
		}
		if anchor.Status != registry.Active || !anchor.Interval.Current(now, registry.ClockError) {
			failed = &anchor.ID
			break
		}
		current = anchor.Parent
	}
	if failed == nil {
		return nil
	}
	item := DecisionSummary{
		RequestID: requestID, Action: pkg.Request.Action, Outcome: "REJECTED", Code: code, FailedObjectID: failed,
		BlockNumber: view.BlockNumber, BlockHash: view.BlockHash, DecisionAt: now.Unix(),
		ProbeTxID: view.Probe.TxID, ProbeDeadline: view.Probe.Deadline.Unix(),
	}
	_, writeErr := s.cfg.DB.Exec(ctx, `INSERT INTO workbench_gateway_rejections(deployment_id,request_id,actor,task_id,observed_at,body)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, s.cfg.DeploymentID, requestID, pkg.Request.Actor, pkg.Request.TaskID, now.Unix(), item)
	return writeErr
}
