package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestGrantSignVerifyAndDelegationChain(t *testing.T) {
	privC, _, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privU, _, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	depID := strings.Repeat("aa", 32)
	taskID := strings.Repeat("bb", 32)
	resourceID := strings.Repeat("cc", 32)
	g0ID := strings.Repeat("10", 32)
	g1ID := strings.Repeat("20", 32)

	now := time.Now().UTC().Truncate(time.Second)
	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(24 * time.Hour).Unix()

	g0Claims := GrantClaims{
		ID:                  g0ID,
		SchemaVersion:       SchemaVersion,
		DeploymentID:        depID,
		RootID:              g0ID,
		TaskID:              taskID,
		AuthorizationMode:   ModeResourcePreauthorized,
		PrincipalDomain:     "A",
		ResourceID:          resourceID,
		Issuer:              "did:web:c.local:supplier",
		Grantee:             "did:web:a.local:u",
		IssuerKeyVersion:    1,
		GranteeKeyVersion:   1,
		IssuerCredentialID:  "urn:grad:credential:C-v1",
		GranteeCredentialID: "urn:grad:credential:U-v1",
		Resources:           []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:             []string{"order.create", "quote.read"},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      100000,
		NBF:                 nbf,
		EXP:                 exp,
		RemainingDepth:      2,
	}
	g0JWS, g0Digest, err := SignGrant(privC, "did:web:c.local:supplier#key-1", &g0Claims)
	if err != nil {
		t.Fatalf("SignGrant G0: %v", err)
	}
	sum0 := sha256.Sum256([]byte(g0JWS))
	if g0Digest != hex.EncodeToString(sum0[:]) {
		t.Fatalf("G0 digest mismatch")
	}

	g1Claims := GrantClaims{
		ID:                  g1ID,
		SchemaVersion:       SchemaVersion,
		DeploymentID:        depID,
		ParentID:            &g0ID,
		ParentDigest:        &g0Digest,
		RootID:              g0ID,
		TaskID:              taskID,
		AuthorizationMode:   ModeResourcePreauthorized,
		PrincipalDomain:     "A",
		ResourceID:          resourceID,
		Issuer:              "did:web:a.local:u",
		Grantee:             "did:web:b.local:broker",
		IssuerKeyVersion:    1,
		GranteeKeyVersion:   1,
		IssuerCredentialID:  "urn:grad:credential:U-v1",
		GranteeCredentialID: "urn:grad:credential:B-v1",
		Resources:           []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:             []string{"order.create", "quote.read"},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      90000,
		NBF:                 nbf + 10,
		EXP:                 exp - 10,
		RemainingDepth:      1,
	}
	g1JWS, _, err := SignGrant(privU, "did:web:a.local:u#key-1", &g1Claims)
	if err != nil {
		t.Fatalf("SignGrant G1: %v", err)
	}

	pg0, err := ParseAndVerifyGrant(g0JWS, &privC.PublicKey, "did:web:c.local:supplier#key-1")
	if err != nil {
		t.Fatalf("ParseAndVerifyGrant G0: %v", err)
	}
	pg1, err := ParseAndVerifyGrant(g1JWS, &privU.PublicKey, "did:web:a.local:u#key-1")
	if err != nil {
		t.Fatalf("ParseAndVerifyGrant G1: %v", err)
	}
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pg1}); err != nil {
		t.Fatalf("VerifyGrantChain: %v", err)
	}

	// Negative 1: wrong signer key
	if _, err := ParseAndVerifyGrant(g0JWS, &privU.PublicKey, "did:web:c.local:supplier#key-1"); !HasCode(err, ErrCodeSignatureInvalid) {
		t.Fatalf("expected SIGNATURE_INVALID for wrong grant signer, got %v", err)
	}

	// Negative 2: child widens maxAmountMinor above parent
	badAmount := g1Claims
	badAmount.MaxAmountMinor = 150000
	badAmountJWS, _, _ := SignGrant(privU, "did:web:a.local:u#key-1", &badAmount)
	pgBadAmount, err := ParseAndVerifyGrant(badAmountJWS, &privU.PublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pgBadAmount}); !HasCode(err, ErrCodeGrantChainInvalid) {
		t.Fatalf("expected GRANT_CHAIN_INVALID when child amount exceeds parent, got %v", err)
	}

	// Negative 3: child widens action outside parent
	badAct := g1Claims
	badAct.Actions = []string{"order.cancel", "order.create"}
	badActJWS, _, _ := SignGrant(privU, "did:web:a.local:u#key-1", &badAct)
	pgBadAct, _ := ParseAndVerifyGrant(badActJWS, &privU.PublicKey, "")
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pgBadAct}); !HasCode(err, ErrCodeGrantChainInvalid) {
		t.Fatalf("expected GRANT_CHAIN_INVALID when child widens actions, got %v", err)
	}

	// Negative 4: remainingDepth fails to decrement
	badDepth := g1Claims
	badDepth.RemainingDepth = 2
	badDepthJWS, _, _ := SignGrant(privU, "did:web:a.local:u#key-1", &badDepth)
	pgBadDepth, _ := ParseAndVerifyGrant(badDepthJWS, &privU.PublicKey, "")
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pgBadDepth}); !HasCode(err, ErrCodeGrantChainInvalid) {
		t.Fatalf("expected GRANT_CHAIN_INVALID when remainingDepth does not decrease, got %v", err)
	}

	// Negative 5: child window exceeds parent EXP
	badExp := g1Claims
	badExp.EXP = exp + 60
	badExpJWS, _, _ := SignGrant(privU, "did:web:a.local:u#key-1", &badExp)
	pgBadExp, _ := ParseAndVerifyGrant(badExpJWS, &privU.PublicKey, "")
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pgBadExp}); !HasCode(err, ErrCodeGrantChainInvalid) {
		t.Fatalf("expected GRANT_CHAIN_INVALID when child exp > parent exp, got %v", err)
	}

	// Negative 6: parentDigest mismatch
	badParentDigest := g1Claims
	wrongDig := strings.Repeat("ef", 32)
	badParentDigest.ParentDigest = &wrongDig
	badDigJWS, _, _ := SignGrant(privU, "did:web:a.local:u#key-1", &badParentDigest)
	pgBadDig, _ := ParseAndVerifyGrant(badDigJWS, &privU.PublicKey, "")
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pgBadDig}); !HasCode(err, ErrCodeGrantChainInvalid) {
		t.Fatalf("expected GRANT_CHAIN_INVALID when parentDigest mismatches, got %v", err)
	}

	// Negative 7: wildcard action rejected in schema
	wildcard := g0Claims
	wildcard.Actions = []string{"*"}
	if err := wildcard.ValidateStructure(); !HasCode(err, ErrCodeInvalidSchema) {
		t.Fatalf("expected INVALID_SCHEMA for wildcard action, got %v", err)
	}
}

func TestTwoHopGrantChainErrorCodes(t *testing.T) {
	privPA, _, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privU, _, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privA1, _, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	depID := strings.Repeat("bb", 32)
	taskID := strings.Repeat("cc", 32)
	g0ID := strings.Repeat("d0", 32)
	g1ID := strings.Repeat("d1", 32)
	g2ID := strings.Repeat("d2", 32)
	now := time.Now().UTC().Unix()
	nbf, exp := now-60, now+3600

	g0Claims := GrantClaims{
		ID: g0ID, SchemaVersion: SchemaVersion, DeploymentID: depID, RootID: g0ID, TaskID: taskID,
		AuthorizationMode: ModeBuyerMandate, PrincipalDomain: "A", ResourceID: "urn:grad:resource:C:orders",
		Issuer: "did:web:a.local:pa", Grantee: "did:web:a.local:u",
		IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredentialID: "urn:grad:credential:PA-v1", GranteeCredentialID: "urn:grad:credential:U-v1",
		Resources: []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:   []string{"order.create", "quote.read"}, Suppliers: []string{"urn:grad:supplier:C"},
		Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 2,
	}
	g0JWS, g0Dig, err := SignGrant(privPA, "did:web:a.local:pa#key-1", &g0Claims)
	if err != nil {
		t.Fatal(err)
	}
	g1Claims := GrantClaims{
		ID: g1ID, SchemaVersion: SchemaVersion, DeploymentID: depID, ParentID: &g0ID, ParentDigest: &g0Dig,
		RootID: g0ID, TaskID: taskID, AuthorizationMode: ModeBuyerMandate, PrincipalDomain: "A",
		ResourceID: "urn:grad:resource:C:orders", Issuer: "did:web:a.local:u", Grantee: "did:web:a.local:a1",
		IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredentialID: "urn:grad:credential:U-v1", GranteeCredentialID: "urn:grad:credential:A1-v1",
		Resources: []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:   []string{"order.create", "quote.read"}, Suppliers: []string{"urn:grad:supplier:C"},
		Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 1,
	}
	g1JWS, g1Dig, err := SignGrant(privU, "did:web:a.local:u#key-1", &g1Claims)
	if err != nil {
		t.Fatal(err)
	}
	g2Claims := GrantClaims{
		ID: g2ID, SchemaVersion: SchemaVersion, DeploymentID: depID, ParentID: &g1ID, ParentDigest: &g1Dig,
		RootID: g0ID, TaskID: taskID, AuthorizationMode: ModeBuyerMandate, PrincipalDomain: "A",
		ResourceID: "urn:grad:resource:C:orders", Issuer: "did:web:a.local:a1", Grantee: "did:web:b.local:b1",
		IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredentialID: "urn:grad:credential:A1-v1", GranteeCredentialID: "urn:grad:credential:B1-v1",
		Resources: []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:   []string{"order.create", "quote.read"}, Suppliers: []string{"urn:grad:supplier:C"},
		Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 100000, NBF: nbf, EXP: exp, RemainingDepth: 0,
	}
	g2JWS, _, err := SignGrant(privA1, "did:web:a.local:a1#key-1", &g2Claims)
	if err != nil {
		t.Fatal(err)
	}
	pg0, _ := ParseAndVerifyGrant(g0JWS, &privPA.PublicKey, "")
	pg1, _ := ParseAndVerifyGrant(g1JWS, &privU.PublicKey, "")
	pg2, _ := ParseAndVerifyGrant(g2JWS, &privA1.PublicKey, "")
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pg1, pg2}); err != nil {
		t.Fatalf("expected valid 2-hop BM chain, got %v", err)
	}

	// Expansion -> DELEGATION_EXPANSION + GRANT_CHAIN_INVALID
	expG2 := g2Claims
	expG2.MaxAmountMinor = 600000
	expG2JWS, _, _ := SignGrant(privA1, "did:web:a.local:a1#key-1", &expG2)
	pgExpG2, _ := ParseAndVerifyGrant(expG2JWS, &privA1.PublicKey, "")
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pg1, pgExpG2}); !HasCode(err, ErrCodeDelegationExpansion) || !HasCode(err, ErrCodeGrantChainInvalid) {
		t.Fatalf("expected DELEGATION_EXPANSION + GRANT_CHAIN_INVALID, got %v", err)
	}

	// Mode mismatch -> AUTHORIZATION_MODE_MISMATCH + GRANT_CHAIN_INVALID
	modeG2 := g2Claims
	modeG2.AuthorizationMode = ModeResourcePreauthorized
	modeG2JWS, _, _ := SignGrant(privA1, "did:web:a.local:a1#key-1", &modeG2)
	pgModeG2, _ := ParseAndVerifyGrant(modeG2JWS, &privA1.PublicKey, "")
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pg1, pgModeG2}); !HasCode(err, ErrCodeAuthorizationModeMismatch) || !HasCode(err, ErrCodeGrantChainInvalid) {
		t.Fatalf("expected AUTHORIZATION_MODE_MISMATCH, got %v", err)
	}

	// Skipping G1 (G0 -> G2) -> PATH_INVALID
	if err := VerifyGrantChain([]*ParsedGrant{pg0, pg2}); !HasCode(err, ErrCodePathInvalid) || !HasCode(err, ErrCodeGrantChainInvalid) {
		t.Fatalf("expected PATH_INVALID when skipping G1, got %v", err)
	}
}
