package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrantSignVerifyAndDelegationChain(t *testing.T) {
	privC, _ := mustGenKeyPair(t)
	privU, _ := mustGenKeyPair(t)
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
		Resources:           []string{ResourceOrders, ResourceQuotes},
		Actions:             []string{ActionOrderCreate, ActionQuoteRead},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      100000,
		NBF:                 nbf,
		EXP:                 exp,
		RemainingDepth:      2,
	}
	g0JWS, g0Digest, err := SignGrant(privC, "did:web:c.local:supplier#key-1", &g0Claims)
	require.NoError(t, err)
	sum0 := sha256.Sum256([]byte(g0JWS))
	assert.Equal(t, hex.EncodeToString(sum0[:]), g0Digest)

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
		Resources:           []string{ResourceOrders, ResourceQuotes},
		Actions:             []string{ActionOrderCreate, ActionQuoteRead},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      90000,
		NBF:                 nbf + 10,
		EXP:                 exp - 10,
		RemainingDepth:      1,
	}
	g1JWS, _, err := SignGrant(privU, "did:web:a.local:u#key-1", &g1Claims)
	require.NoError(t, err)

	pg0, err := ParseAndVerifyGrant(g0JWS, &privC.PublicKey, "did:web:c.local:supplier#key-1")
	require.NoError(t, err)
	pg1, err := ParseAndVerifyGrant(g1JWS, &privU.PublicKey, "did:web:a.local:u#key-1")
	require.NoError(t, err)
	require.NoError(t, VerifyGrantChain([]*ParsedGrant{pg0, pg1}))

	// Negative 1: wrong signer key.
	_, err = ParseAndVerifyGrant(g0JWS, &privU.PublicKey, "did:web:c.local:supplier#key-1")
	assert.True(t, HasCode(err, ErrCodeSignatureInvalid), "got %v", err)

	// Negative 2: child widens maxAmountMinor above parent.
	badAmount := g1Claims
	badAmount.MaxAmountMinor = 150000
	badAmountJWS, _, err := SignGrant(privU, "did:web:a.local:u#key-1", &badAmount)
	require.NoError(t, err)
	pgBadAmount, err := ParseAndVerifyGrant(badAmountJWS, &privU.PublicKey, "")
	require.NoError(t, err)
	err = VerifyGrantChain([]*ParsedGrant{pg0, pgBadAmount})
	assert.True(t, HasCode(err, ErrCodeDelegationExpansion) && HasCode(err, ErrCodeGrantChainInvalid), "got %v", err)

	// Negative 3: child widens actions outside parent.
	badAct := g1Claims
	badAct.Actions = []string{"order.cancel", ActionOrderCreate}
	badActJWS, _, err := SignGrant(privU, "did:web:a.local:u#key-1", &badAct)
	require.NoError(t, err)
	pgBadAct, err := ParseAndVerifyGrant(badActJWS, &privU.PublicKey, "")
	require.NoError(t, err)
	err = VerifyGrantChain([]*ParsedGrant{pg0, pgBadAct})
	assert.True(t, HasCode(err, ErrCodeDelegationExpansion) && HasCode(err, ErrCodeGrantChainInvalid), "got %v", err)

	// Negative 4: remainingDepth fails to decrement.
	badDepth := g1Claims
	badDepth.RemainingDepth = 2
	badDepthJWS, _, err := SignGrant(privU, "did:web:a.local:u#key-1", &badDepth)
	require.NoError(t, err)
	pgBadDepth, err := ParseAndVerifyGrant(badDepthJWS, &privU.PublicKey, "")
	require.NoError(t, err)
	err = VerifyGrantChain([]*ParsedGrant{pg0, pgBadDepth})
	assert.True(t, HasCode(err, ErrCodeDelegationExpansion) && HasCode(err, ErrCodeGrantChainInvalid), "got %v", err)

	// Negative 5: child window exceeds parent EXP.
	badExp := g1Claims
	badExp.EXP = exp + 60
	badExpJWS, _, err := SignGrant(privU, "did:web:a.local:u#key-1", &badExp)
	require.NoError(t, err)
	pgBadExp, err := ParseAndVerifyGrant(badExpJWS, &privU.PublicKey, "")
	require.NoError(t, err)
	err = VerifyGrantChain([]*ParsedGrant{pg0, pgBadExp})
	assert.True(t, HasCode(err, ErrCodeDelegationExpansion) && HasCode(err, ErrCodeGrantChainInvalid), "got %v", err)

	// Negative 6: parentDigest mismatch.
	badParentDigest := g1Claims
	wrongDig := strings.Repeat("ef", 32)
	badParentDigest.ParentDigest = &wrongDig
	badDigJWS, _, err := SignGrant(privU, "did:web:a.local:u#key-1", &badParentDigest)
	require.NoError(t, err)
	pgBadDig, err := ParseAndVerifyGrant(badDigJWS, &privU.PublicKey, "")
	require.NoError(t, err)
	err = VerifyGrantChain([]*ParsedGrant{pg0, pgBadDig})
	assert.True(t, HasCode(err, ErrCodePathInvalid) && HasCode(err, ErrCodeGrantChainInvalid), "got %v", err)

	// Negative 7: wildcard action rejected in schema.
	wildcard := g0Claims
	wildcard.Actions = []string{"*"}
	assert.True(t, HasCode(wildcard.ValidateStructure(), ErrCodeInvalidSchema))

	// Negative 8: legacy non-canonical resource aliases rejected in grant.resources.
	for _, legacyRes := range []string{"quotes", "orders", "urn:grad:resource:quotes", "urn:grad:resource:orders"} {
		badRes := g0Claims
		badRes.Resources = []string{legacyRes}
		assert.True(t, HasCode(badRes.ValidateStructure(), ErrCodeInvalidSchema), "legacyRes=%q", legacyRes)
	}
}

func TestTwoHopGrantChainErrorCodes(t *testing.T) {
	privPA, _ := mustGenKeyPair(t)
	privU, _ := mustGenKeyPair(t)
	privA1, _ := mustGenKeyPair(t)
	depID := strings.Repeat("bb", 32)
	taskID := strings.Repeat("cc", 32)
	g0ID := strings.Repeat("d0", 32)
	g1ID := strings.Repeat("d1", 32)
	g2ID := strings.Repeat("d2", 32)
	now := time.Now().UTC().Unix()
	nbf, exp := now-60, now+3600

	g0Claims := GrantClaims{
		ID: g0ID, SchemaVersion: SchemaVersion, DeploymentID: depID, RootID: g0ID, TaskID: taskID,
		AuthorizationMode: ModeBuyerMandate, PrincipalDomain: "A", ResourceID: ResourceOrders,
		Issuer: "did:web:a.local:pa", Grantee: "did:web:a.local:u",
		IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredentialID: "urn:grad:credential:PA-v1", GranteeCredentialID: "urn:grad:credential:U-v1",
		Resources: []string{ResourceOrders, ResourceQuotes},
		Actions:   []string{ActionOrderCreate, ActionQuoteRead}, Suppliers: []string{"urn:grad:supplier:C"},
		Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 2,
	}
	g0JWS, g0Dig, err := SignGrant(privPA, "did:web:a.local:pa#key-1", &g0Claims)
	require.NoError(t, err)

	g1Claims := GrantClaims{
		ID: g1ID, SchemaVersion: SchemaVersion, DeploymentID: depID, ParentID: &g0ID, ParentDigest: &g0Dig,
		RootID: g0ID, TaskID: taskID, AuthorizationMode: ModeBuyerMandate, PrincipalDomain: "A",
		ResourceID: ResourceOrders, Issuer: "did:web:a.local:u", Grantee: "did:web:a.local:a1",
		IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredentialID: "urn:grad:credential:U-v1", GranteeCredentialID: "urn:grad:credential:A1-v1",
		Resources: []string{ResourceOrders, ResourceQuotes},
		Actions:   []string{ActionOrderCreate, ActionQuoteRead}, Suppliers: []string{"urn:grad:supplier:C"},
		Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 1,
	}
	g1JWS, g1Dig, err := SignGrant(privU, "did:web:a.local:u#key-1", &g1Claims)
	require.NoError(t, err)

	g2Claims := GrantClaims{
		ID: g2ID, SchemaVersion: SchemaVersion, DeploymentID: depID, ParentID: &g1ID, ParentDigest: &g1Dig,
		RootID: g0ID, TaskID: taskID, AuthorizationMode: ModeBuyerMandate, PrincipalDomain: "A",
		ResourceID: ResourceOrders, Issuer: "did:web:a.local:a1", Grantee: "did:web:b.local:b1",
		IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredentialID: "urn:grad:credential:A1-v1", GranteeCredentialID: "urn:grad:credential:B1-v1",
		Resources: []string{ResourceOrders, ResourceQuotes},
		Actions:   []string{ActionOrderCreate, ActionQuoteRead}, Suppliers: []string{"urn:grad:supplier:C"},
		Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 100000, NBF: nbf, EXP: exp, RemainingDepth: 0,
	}
	g2JWS, _, err := SignGrant(privA1, "did:web:a.local:a1#key-1", &g2Claims)
	require.NoError(t, err)

	pg0, err := ParseAndVerifyGrant(g0JWS, &privPA.PublicKey, "")
	require.NoError(t, err)
	pg1, err := ParseAndVerifyGrant(g1JWS, &privU.PublicKey, "")
	require.NoError(t, err)
	pg2, err := ParseAndVerifyGrant(g2JWS, &privA1.PublicKey, "")
	require.NoError(t, err)
	require.NoError(t, VerifyGrantChain([]*ParsedGrant{pg0, pg1, pg2}))

	// Expansion -> DELEGATION_EXPANSION + GRANT_CHAIN_INVALID.
	expG2 := g2Claims
	expG2.MaxAmountMinor = 600000
	expG2JWS, _, err := SignGrant(privA1, "did:web:a.local:a1#key-1", &expG2)
	require.NoError(t, err)
	pgExpG2, err := ParseAndVerifyGrant(expG2JWS, &privA1.PublicKey, "")
	require.NoError(t, err)
	err = VerifyGrantChain([]*ParsedGrant{pg0, pg1, pgExpG2})
	assert.True(t, HasCode(err, ErrCodeDelegationExpansion) && HasCode(err, ErrCodeGrantChainInvalid), "got %v", err)

	// Mode mismatch -> AUTHORIZATION_MODE_MISMATCH + GRANT_CHAIN_INVALID.
	modeG2 := g2Claims
	modeG2.AuthorizationMode = ModeResourcePreauthorized
	modeG2JWS, _, err := SignGrant(privA1, "did:web:a.local:a1#key-1", &modeG2)
	require.NoError(t, err)
	pgModeG2, err := ParseAndVerifyGrant(modeG2JWS, &privA1.PublicKey, "")
	require.NoError(t, err)
	err = VerifyGrantChain([]*ParsedGrant{pg0, pg1, pgModeG2})
	assert.True(t, HasCode(err, ErrCodeAuthorizationModeMismatch) && HasCode(err, ErrCodeGrantChainInvalid), "got %v", err)

	// Skipping G1 (G0 -> G2) -> PATH_INVALID + GRANT_CHAIN_INVALID.
	err = VerifyGrantChain([]*ParsedGrant{pg0, pg2})
	assert.True(t, HasCode(err, ErrCodePathInvalid) && HasCode(err, ErrCodeGrantChainInvalid), "got %v", err)
}
