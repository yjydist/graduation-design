package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPublishedFabricBindings(t *testing.T) {
	data, err := os.ReadFile("../../docs/IMPLEMENTATION.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(data), "### 3.4 部署绑定与管理证明")
	_, body, fence := strings.Cut(section, "```json\n")
	raw, _, end := strings.Cut(body, "\n```")
	if !found || !fence || !end {
		t.Fatal("published Fabric binding vector missing")
	}
	var v struct {
		Deployment               DeploymentFields
		DeploymentID             string
		Challenge                map[string]any
		ChallengeSHA256          string
		ManagementCertificateDER string
		ManagementSignatureDER   string
		AppJWSProtected          string
		AppJWSSignature          string
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	if !v.Deployment.Valid() {
		t.Fatal("published deployment fields failed Valid()")
	}
	if v.Deployment.DeploymentID() != v.DeploymentID || v.Challenge["deploymentId"] != v.DeploymentID {
		t.Fatalf("deployment digest mismatch: got %s want %s", v.Deployment.DeploymentID(), v.DeploymentID)
	}
	// Empty Purpose must default to DeploymentPurpose and yield the identical DeploymentID.
	noPurpose := v.Deployment
	noPurpose.Purpose = ""
	if !noPurpose.Valid() || noPurpose.DeploymentID() != v.DeploymentID {
		t.Fatal("deployment without explicit purpose should match canonical DeploymentID")
	}
	badPurpose := v.Deployment
	badPurpose.Purpose = "wrong-purpose"
	if badPurpose.Valid() {
		t.Fatal("deployment with invalid purpose must fail Valid()")
	}

	b64 := func(s string) []byte {
		t.Helper()
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cert, err := x509.ParseCertificate(b64(v.ManagementCertificateDER))
	if err != nil {
		t.Fatal(err)
	}
	mgmt, ok := cert.PublicKey.(*ecdsa.PublicKey)
	binding := v.Challenge["managementIdentity"].(map[string]any)
	m := Management{
		MSPID:             binding["mspId"].(string),
		CertificateSHA256: binding["certificateSha256"].(string),
	}
	if !ok || !m.Valid() || m.MSPID != "AMsp" || m.CertificateSHA256 != Digest(cert.Raw) {
		t.Fatal("certificate binding mismatch")
	}

	appPubHex := v.Challenge["appPublicKey"].(string)
	if !ValidAppKey(v.Challenge["subjectId"].(string), v.Challenge["appKeyId"].(string), appPubHex, 1) {
		t.Fatal("published vector app key failed ValidAppKey")
	}
	app, err := ParseAppPublicKey(appPubHex)
	if err != nil {
		t.Fatalf("ParseAppPublicKey: %v", err)
	}
	sig := b64(v.AppJWSSignature)
	if mgmt.Equal(app) || len(sig) != 64 {
		t.Fatal("invalid distinct application key or ES256 signature")
	}

	canonical := func() []byte {
		t.Helper()
		raw, err := json.Marshal(v.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	verify := func(c []byte) (bool, bool) {
		hash := sha256.Sum256(c)
		appHash := sha256.Sum256([]byte(v.AppJWSProtected + "." + base64.RawURLEncoding.EncodeToString(c)))
		return ecdsa.VerifyASN1(mgmt, hash[:], b64(v.ManagementSignatureDER)),
			ecdsa.Verify(app, appHash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	validManagement, validApp := verify(canonical())
	if !validManagement || !validApp || Digest(canonical()) != v.ChallengeSHA256 {
		t.Fatal("challenge proof mismatch")
	}
	for _, field := range []string{"deploymentId", "nonce"} {
		old := v.Challenge[field]
		v.Challenge[field] = "changed"
		if management, appOK := verify(canonical()); management || appOK {
			t.Fatalf("changed %s retained a valid proof", field)
		}
		v.Challenge[field] = old
	}
}

func TestErrorCodesAndHelpers(t *testing.T) {
	if len(knownErrorCodes) != 67 {
		t.Fatalf("expected 67 canonical error codes (58 protocol + 6 registry + 3 management), got %d", len(knownErrorCodes))
	}
	for code := range knownErrorCodes {
		if strings.HasPrefix(code, "D0:") {
			t.Fatalf("canonical code %q must not have D0: prefix", code)
		}
		if !IsKnownCode(code) {
			t.Fatalf("IsKnownCode(%q) = false", code)
		}
	}
	if IsKnownCode("D0:UNAUTHORIZED") || IsKnownCode("UNKNOWN_CODE") || IsKnownCode("") {
		t.Fatal("unknown or prefixed error code must not be recognized as known")
	}

	// Reject emits the exact canonical code without any legacy prefix.
	rej := Reject(ErrCodeUnauthorized)
	if rej.Error() != ErrCodeUnauthorized {
		t.Fatalf("Reject error text = %q, want %q", rej.Error(), ErrCodeUnauthorized)
	}
	if CodeOf(rej) != ErrCodeUnauthorized || !HasCode(rej, ErrCodeUnauthorized) {
		t.Fatal("CodeOf/HasCode failed on Reject error")
	}

	// NewError and WrapError preserve code, message, and cause chain.
	ne := NewError(ErrCodeInvalidSchema, "missing field")
	if ne.Error() != "INVALID_SCHEMA: missing field" {
		t.Fatalf("NewError text = %q", ne.Error())
	}
	if CodeOf(ne) != ErrCodeInvalidSchema || !HasCode(ne, ErrCodeInvalidSchema) {
		t.Fatal("CodeOf/HasCode failed on NewError")
	}

	inner := NewError(ErrCodeStateChanged, "revision mismatch")
	wrapped := WrapError(ErrCodeGrantStateConflict, "replace failed", inner)
	if !errors.Is(wrapped, inner) {
		t.Fatal("WrapError did not preserve cause for errors.Is")
	}
	if CodeOf(wrapped) != ErrCodeGrantStateConflict {
		t.Fatalf("CodeOf(wrapped) = %q, want %q", CodeOf(wrapped), ErrCodeGrantStateConflict)
	}
	if !HasCode(wrapped, ErrCodeGrantStateConflict) || !HasCode(wrapped, ErrCodeStateChanged) {
		t.Fatal("HasCode failed to match outer or inner error code in chain")
	}
	if HasCode(wrapped, ErrCodePolicyDenied) {
		t.Fatal("HasCode matched unrelated code")
	}

	// Plain canonical code errors (e.g. returned from chaincode shim) and wrapped forms.
	plain := errors.New(ErrCodeAlreadyRevoked)
	if CodeOf(plain) != ErrCodeAlreadyRevoked || !HasCode(plain, ErrCodeAlreadyRevoked) {
		t.Fatal("CodeOf/HasCode failed on plain canonical code error")
	}
	fmtWrapped := fmt.Errorf("endorsement failed: %w", plain)
	if CodeOf(fmtWrapped) != ErrCodeAlreadyRevoked || !HasCode(fmtWrapped, ErrCodeAlreadyRevoked) {
		t.Fatal("CodeOf/HasCode failed on fmt.Errorf wrapped plain code")
	}
	prefixedMsg := errors.New("INVALID_DISCLOSURE: duplicate salt")
	if CodeOf(prefixedMsg) != ErrCodeInvalidDisclosure || !HasCode(prefixedMsg, ErrCodeInvalidDisclosure) {
		t.Fatal("CodeOf/HasCode failed on stringified protocol error")
	}

	// Legacy D0: prefixed errors must NOT be recognized.
	legacy := errors.New("D0:UNAUTHORIZED")
	if CodeOf(legacy) != "" || HasCode(legacy, ErrCodeUnauthorized) {
		t.Fatal("legacy D0: prefixed error must not match canonical codes")
	}
	if CodeOf(nil) != "" || HasCode(nil, ErrCodeUnauthorized) || HasCode(rej, "") {
		t.Fatal("nil error or empty code must return empty/false")
	}
}

func TestValidAppKey(t *testing.T) {
	// P-256 generator G from Section 1.4 vector.
	const validPubHex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	const validDID = "did:web:example.test:subjects:vector"
	const validKeyID = "did:web:example.test:subjects:vector#key-1"

	if !ValidAppKey(validDID, validKeyID, validPubHex, 1) {
		t.Fatal("expected valid P-256 uncompressed key to pass")
	}
	// Compressed key (33 bytes -> 66 hex chars).
	compressed := "03" + validPubHex[2:66]
	// Off-curve point (flip last nibble).
	offCurve := validPubHex[:len(validPubHex)-1] + "4"
	// All-zero 65 bytes / infinity.
	allZero := strings.Repeat("00", 65)
	// Wrong prefix (0x02 with 65 bytes).
	wrongPrefix := "02" + validPubHex[2:]
	// Uppercase hex.
	upperHex := strings.ToUpper(validPubHex)

	cases := []struct {
		name    string
		id      string
		keyID   string
		pub     string
		version uint64
	}{
		{"empty did", "", validKeyID, validPubHex, 1},
		{"bare did:web:", "did:web:", "did:web:#k", validPubHex, 1},
		{"non-web did", "did:key:z123", "did:key:z123#k", validPubHex, 1},
		{"missing fragment", validDID, validDID + "#", validPubHex, 1},
		{"mismatched key prefix", validDID, "did:web:other.test#key-1", validPubHex, 1},
		{"zero version", validDID, validKeyID, validPubHex, 0},
		{"compressed point", validDID, validKeyID, compressed, 1},
		{"off curve point", validDID, validKeyID, offCurve, 1},
		{"all zeros", validDID, validKeyID, allZero, 1},
		{"wrong prefix", validDID, validKeyID, wrongPrefix, 1},
		{"uppercase hex", validDID, validKeyID, upperHex, 1},
		{"invalid hex", validDID, validKeyID, "zz" + validPubHex[2:], 1},
	}
	for _, tc := range cases {
		if ValidAppKey(tc.id, tc.keyID, tc.pub, tc.version) {
			t.Fatalf("case %q: expected ValidAppKey to reject", tc.name)
		}
	}

	// Verify ParseAppPublicKey returns a real P-256 key on elliptic.P256().
	pub, err := ParseAppPublicKey(validPubHex)
	if err != nil {
		t.Fatalf("ParseAppPublicKey: %v", err)
	}
	if pub.Curve != elliptic.P256() {
		t.Fatal("parsed key curve is not P-256")
	}
}

func TestValidStringSetAndUTF16Order(t *testing.T) {
	if !ValidStringSet([]string{"domain", "role"}) {
		t.Fatal("expected valid sorted set to pass")
	}
	// RFC 8785 UTF-16 code unit ordering: U+10000 (surrogate 0xD800, 0xDC00) sorts BEFORE U+E000 (0xE000),
	// whereas UTF-8 byte order puts U+E000 (0xEE 0x80 0x80) before U+10000 (0xF0 0x90 0x80 0x80).
	u10000 := string(rune(0x10000))
	uE000 := string(rune(0xE000))
	if CompareUTF16(u10000, uE000) >= 0 {
		t.Fatal("CompareUTF16 must sort U+10000 before U+E000 per RFC 8785")
	}
	if !ValidStringSet([]string{u10000, uE000}) {
		t.Fatal("ValidStringSet must accept UTF-16 ascending order")
	}
	if ValidStringSet([]string{uE000, u10000}) {
		t.Fatal("ValidStringSet must reject UTF-8 order that violates UTF-16 order")
	}

	// Reject empty, duplicates, unsorted, wildcards, invalid UTF-8, and > 64 entries.
	if ValidStringSet(nil) || ValidStringSet([]string{}) {
		t.Fatal("empty set must be rejected")
	}
	if ValidStringSet([]string{"a", ""}) {
		t.Fatal("empty element must be rejected")
	}
	if ValidStringSet([]string{"a", "a"}) {
		t.Fatal("duplicate element must be rejected")
	}
	if ValidStringSet([]string{"role", "domain"}) {
		t.Fatal("unsorted set must be rejected")
	}
	if ValidStringSet([]string{"*"}) || ValidStringSet([]string{"role*"}) {
		t.Fatal("wildcard element must be rejected")
	}
	if ValidStringSet([]string{string([]byte{0xff, 0xfe})}) {
		t.Fatal("invalid UTF-8 must be rejected")
	}
	tooMany := make([]string, MaxIssuerTypesOrClaims+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("claim-%03d", i)
	}
	if ValidStringSet(tooMany) {
		t.Fatal("set exceeding MaxIssuerTypesOrClaims must be rejected")
	}
	if !ValidStringSet(tooMany[:MaxIssuerTypesOrClaims]) {
		t.Fatal("set with exactly MaxIssuerTypesOrClaims items should be accepted")
	}
}

func TestIntervalIssuerScopeBoundAndKeys(t *testing.T) {
	parent := Interval{NBF: 1000, EXP: 2000}
	child := Interval{NBF: 1100, EXP: 1900}
	if !parent.Valid() || !child.Valid() || !child.Within(parent) || parent.Within(child) {
		t.Fatal("interval Valid/Within check failed")
	}
	if (Interval{NBF: 0, EXP: 100}).Valid() || (Interval{NBF: 100, EXP: 100}).Valid() || (Interval{NBF: 100, EXP: MaxUnixTimestamp + 1}).Valid() {
		t.Fatal("invalid interval boundaries must fail Valid()")
	}
	margin := 3 * time.Second
	if !parent.Current(time.Unix(1003, 0), margin) {
		t.Fatal("expected t=1003 with margin=3s to be current for [1000, 2000)")
	}
	if parent.Current(time.Unix(1002, 0), margin) {
		t.Fatal("expected t=1002 with margin=3s to fail lower bound")
	}
	if parent.Current(time.Unix(1997, 0), margin) {
		t.Fatal("expected t=1997 with margin=3s to fail right-open upper bound")
	}
	if !parent.Current(time.Unix(1996, 0), margin) {
		t.Fatal("expected t=1996 with margin=3s to pass upper bound")
	}

	// IssuerScope validation and JSON tag verification.
	scope := IssuerScope{
		ID:              "did:web:buyer-a.example.test:issuers:IA",
		AppKeyVersion:   1,
		CredentialTypes: []string{"EnterpriseIdentityCredential"},
		ClaimNames:      []string{"domain", "role"},
	}
	if !scope.Valid() {
		t.Fatal("expected valid IssuerScope to pass")
	}
	rawScope, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	const wantScopeJSON = `{"id":"did:web:buyer-a.example.test:issuers:IA","appKeyVersion":1,"credentialTypes":["EnterpriseIdentityCredential"],"claimNames":["domain","role"]}`
	if string(rawScope) != wantScopeJSON {
		t.Fatalf("IssuerScope JSON = %s, want %s", rawScope, wantScopeJSON)
	}
	badScope := scope
	badScope.AppKeyVersion = 0
	if badScope.Valid() {
		t.Fatal("IssuerScope with zero AppKeyVersion must fail")
	}

	// Digest, Bound, Key, and ProbeKey.
	d := Digest([]byte("hello"))
	if !IsDigest(d) || IsDigest(strings.Repeat("0", 64)) || IsDigest(strings.ToUpper(d)) || IsDigest("short") {
		t.Fatal("IsDigest validation failed")
	}
	if !(Bound{DeploymentID: d}).Valid() || (Bound{DeploymentID: strings.Repeat("0", 64)}).Valid() {
		t.Fatal("Bound.Valid() failed")
	}
	if got, want := Key("domain", "A"), "domain/"+Digest([]byte("A")); got != want {
		t.Fatalf("Key = %q, want %q", got, want)
	}
	m := Management{MSPID: "AMsp", CertificateSHA256: d}
	if !m.Valid() {
		t.Fatal("Management.Valid() failed")
	}
	if got, want := ProbeKey(m), "probe/"+Digest([]byte("AMsp/"+d)); got != want {
		t.Fatalf("ProbeKey = %q, want %q", got, want)
	}

	// Canonical resource & action constants.
	if ResourceQuotes != "urn:grad:resource:C:quotes" ||
		ResourceOrders != "urn:grad:resource:C:orders" ||
		ActionQuoteRead != "quote.read" ||
		ActionOrderCreate != "order.create" {
		t.Fatal("canonical resource or action constants mismatch")
	}
}
