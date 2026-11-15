package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func delegationWallet(t *testing.T, digest string) (*WalletContext, string) {
	t.Helper()
	now := time.Now()
	w, err := NewWalletContext(WalletConfig{DeploymentID: strings.Repeat("a", 64), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"A1", "B1", "B2"} {
		priv, _, err := protocol.GenerateP256KeyPair()
		if err != nil {
			t.Fatal(err)
		}
		did := "did:web:a.local:" + role
		if err := w.RegisterActor(ActorConfig{Actor: role, DID: did, KeyID: did + "#key-1", KeyVersion: 1, PrivateKey: priv, SDJWTPresentation: "stub~"}); err != nil {
			t.Fatal(err)
		}
	}
	claims := protocol.GrantClaims{
		ID: "parent", RootID: "root", TaskID: "task", ResourceID: "resource",
		SchemaVersion: protocol.SchemaVersion, DeploymentID: w.cfg.DeploymentID,
		Issuer: "did:web:a.local:u", Grantee: "did:web:a.local:A1", PrincipalDomain: "A",
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		IssuerKeyVersion:  1, GranteeKeyVersion: 1, IssuerCredentialID: "cred-u", GranteeCredentialID: "cred-a1",
		Resources: []string{"resource"}, Actions: []string{"order.create"}, Suppliers: []string{"supplier"},
		Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 100000, RemainingDepth: 1,
		NBF: now.Add(-time.Minute).Unix(), EXP: now.Add(time.Hour).Unix(),
	}
	raw := "delivered-parent-material"
	if err := w.AddGrantBundle(GrantBundle{Claims: claims, RawGrantJWS: raw, Digest: digest}); err != nil {
		t.Fatal(err)
	}
	return w, raw
}

func TestDefaultGrantDigestSupportsDelegationAndReplacement(t *testing.T) {
	w, raw := delegationWallet(t, "")
	_, child, err := w.handleDelegateGrant(t.Context(), nil, DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: "parent", GrantID: "child", MaxAmountMinor: 80000,
	})
	if err != nil {
		t.Fatal(err)
	}
	b := w.grants[1]
	if b.Claims.ParentDigest == nil || *b.Claims.ParentDigest != api.Digest([]byte(raw)) {
		t.Fatalf("child parent digest must be SHA-256 hex: %v", b.Claims.ParentDigest)
	}
	_, replacement, err := w.handleReplaceGrant(t.Context(), nil, ReplaceGrantInput{
		IssuerActor: "A1", OldGrantID: child.Grant.GrantID, NewSubjectActor: "B2", NewGrantID: "replacement",
	})
	if err != nil || replacement.RevokedGrantID != "child" || replacement.ReplacementGrant.GrantID != "replacement" {
		t.Fatalf("replacement failed: %+v, %v", replacement, err)
	}
}

func TestSigningErrorsReturnWithoutWalletDeadlock(t *testing.T) {
	for _, tool := range []string{"delegate", "replace"} {
		t.Run(tool, func(t *testing.T) {
			w, _ := delegationWallet(t, "invalid-parent-digest-secret")
			w.RegisterSecret("invalid-parent-digest-secret")
			if tool == "replace" {
				child := *w.grants[0]
				child.Claims.ID = "old-child"
				parentID := "parent"
				child.Claims.ParentID = &parentID
				child.Claims.Issuer = "did:web:a.local:A1"
				child.Claims.Grantee = "did:web:a.local:B1"
				if err := w.AddGrantBundle(child); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				var err error
				if tool == "delegate" {
					_, _, err = w.handleDelegateGrant(context.Background(), nil, DelegateGrantInput{IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: "parent", MaxAmountMinor: 80000})
				} else {
					_, _, err = w.handleReplaceGrant(context.Background(), nil, ReplaceGrantInput{IssuerActor: "A1", OldGrantID: "old-child", NewSubjectActor: "B2"})
				}
				if err == nil {
					done <- nil
					return
				}
				_, _, inspectErr := w.handleInspectWallet(context.Background(), nil, InspectWalletInput{Actor: "A1"})
				if inspectErr != nil {
					done <- inspectErr
					return
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "sign child grant") || strings.Contains(err.Error(), "invalid-parent-digest-secret") {
					t.Fatalf("expected sanitized signing error, got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("signing error deadlocked wallet")
			}
		})
	}
}

func TestMemoryIntentStopRejectsCurrentRevisionAndIsIdempotent(t *testing.T) {
	w, _ := delegationWallet(t, "")
	req := protocol.AccessRequest{Actor: "did:web:a.local:A1", TaskID: "task", Action: "order.create", IdempotencyKey: "memory-stop"}
	act, err := w.beginClientAction(t.Context(), req.Actor, req.TaskID, req.Action, req.IdempotencyKey, "hash", req)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.recordClientActionChallenge(t.Context(), act.ActionID, 1, "challenge-1", "{}"); err != nil {
		t.Fatal(err)
	}
	stopped, _, err := w.stopClientActionSend(t.Context(), req.Actor, req.TaskID, req.Action, req.IdempotencyKey, "case-memory")
	if err != nil {
		t.Fatal(err)
	}
	if err = w.recordClientActionChallenge(t.Context(), act.ActionID, stopped.SendRevision, "challenge-2", "{}"); !protocol.HasCode(err, protocol.ErrCodeStateChanged) {
		t.Fatalf("stopped memory intent accepted current revision: %v", err)
	}
	again, _, err := w.stopClientActionSend(t.Context(), req.Actor, req.TaskID, req.Action, req.IdempotencyKey, "case-memory")
	if err != nil || again.SendRevision != stopped.SendRevision {
		t.Fatalf("repeated stop changed immutable case generation: %+v %v", again, err)
	}
}
