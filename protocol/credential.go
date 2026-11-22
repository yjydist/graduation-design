package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"grad/protocol/registry"
)

const (
	// VCv2ContextURL is the normative W3C VC v2 base context URI.
	VCv2ContextURL = "https://www.w3.org/ns/credentials/v2"
	// GradAuthVocabURI is the inline extension vocabulary namespace for grad-auth-v1 credentials.
	GradAuthVocabURI = "https://grad-auth.example.test/vocab#"
	// PinnedVCv2ContextSHA256 pins the exact SHA-256 hex digest of the bundled local vc-v2.json copy.
	PinnedVCv2ContextSHA256 = "59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734"

	// CredentialTypeVC is the required W3C base credential type.
	CredentialTypeVC = "VerifiableCredential"
	// CredentialTypeDomainAuthority is the business type for T-issued domain authority credentials.
	CredentialTypeDomainAuthority = "DomainAuthorityCredential"
	// CredentialTypeEnterpriseIdentity is the business type for issuer-issued enterprise SD-JWT credentials.
	CredentialTypeEnterpriseIdentity = "EnterpriseIdentityCredential"

	// StatusTypeDomainCertification identifies the ledger status mechanism for domain certifications.
	StatusTypeDomainCertification = "RegistryDomainCertificationStatus"
	// StatusTypeCredential identifies the ledger status mechanism for identity credentials.
	StatusTypeCredential = "RegistryCredentialStatus"

	// MaxIdentityIssuers bounds the number of issuers per DomainAuthorityCredential.
	MaxIdentityIssuers = registry.MaxIdentityIssuers
	// MaxIssuerTypesOrClaims bounds credentialTypes / claimNames per issuer scope.
	MaxIssuerTypesOrClaims = registry.MaxIssuerTypesOrClaims
)

//go:embed contexts/vc-v2.json
var bundledVCv2ContextRaw []byte

// ContextManifestEntry records a pinned offline context artifact for deployment manifests.
type ContextManifestEntry struct {
	URI        string `json:"uri"`
	VocabURI   string `json:"vocabUri"`
	SHA256     string `json:"sha256"`
	JCSSHA256  string `json:"jcsSha256"`
	ByteLength int    `json:"byteLength"`
}

// LocalVCv2Context returns the bundled W3C VC v2 base context bytes after verifying its pinned SHA-256 digest
// and strict I-JSON validity completely offline.
func LocalVCv2Context() ([]byte, ContextManifestEntry, error) {
	return verifyBundledContext(bundledVCv2ContextRaw, PinnedVCv2ContextSHA256)
}

func verifyBundledContext(raw []byte, expectedSHA string) ([]byte, ContextManifestEntry, error) {
	rawDigest := DigestBytes(raw)
	if rawDigest != expectedSHA {
		return nil, ContextManifestEntry{}, NewError(ErrCodeInvalidSchema, fmt.Sprintf("bundled VC v2 context SHA-256 mismatch: got %s, want %s", rawDigest, expectedSHA))
	}
	jcsDigest, err := DigestJCS(raw)
	if err != nil {
		return nil, ContextManifestEntry{}, WrapError(ErrCodeInvalidSchema, "bundled VC v2 context failed strict JSON parse", err)
	}
	var doc struct {
		Context map[string]any `json:"@context"`
	}
	if err := DecodeStrictJSON(raw, &doc); err != nil {
		return nil, ContextManifestEntry{}, WrapError(ErrCodeInvalidSchema, "bundled VC v2 context missing @context object", err)
	}
	if _, ok := doc.Context["VerifiableCredential"]; !ok {
		return nil, ContextManifestEntry{}, NewError(ErrCodeInvalidSchema, "bundled VC v2 context missing VerifiableCredential term")
	}
	entry := ContextManifestEntry{
		URI:        VCv2ContextURL,
		VocabURI:   GradAuthVocabURI,
		SHA256:     rawDigest,
		JCSSHA256:  jcsDigest,
		ByteLength: len(raw),
	}
	return bytes.Clone(raw), entry, nil
}

// DefaultCredentialContext returns a fresh copy of the canonical grad-auth-v1 @context array:
// ["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://grad-auth.example.test/vocab#"}].
func DefaultCredentialContext() []any {
	return []any{
		VCv2ContextURL,
		map[string]string{"@vocab": GradAuthVocabURI},
	}
}

// ValidateCredentialContextRaw enforces that raw JSON @context is strictly:
// ["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://grad-auth.example.test/vocab#"}]
// and verifies the local pinned VC v2 base context without any network IO.
func ValidateCredentialContextRaw(raw []byte) error {
	if _, _, err := LocalVCv2Context(); err != nil {
		return err
	}
	var arr []json.RawMessage
	if err := DecodeStrictJSON(raw, &arr); err != nil {
		return WrapError(ErrCodeInvalidSchema, "credential @context must be a 2-element array", err)
	}
	if len(arr) != 2 {
		return NewError(ErrCodeInvalidSchema, "credential @context must be a 2-element array")
	}
	var first string
	if err := DecodeStrictJSON(arr[0], &first); err != nil || first != VCv2ContextURL {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("credential @context[0] must equal %q", VCv2ContextURL))
	}
	var second struct {
		Vocab string `json:"@vocab"`
	}
	if err := DecodeStrictJSON(arr[1], &second); err != nil {
		return WrapError(ErrCodeInvalidSchema, "credential @context[1] must be a single-key object containing only @vocab", err)
	}
	if second.Vocab != GradAuthVocabURI {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("credential @context[1].@vocab must equal %q", GradAuthVocabURI))
	}
	return nil
}

// ValidateCredentialContext validates an arbitrary Go-typed @context slice/value via JCS round-trip.
func ValidateCredentialContext(ctx any) error {
	canon, err := MarshalJCS(ctx)
	if err != nil {
		return err
	}
	return ValidateCredentialContextRaw(canon)
}

func defaultCredentialContextRaw() (json.RawMessage, error) {
	raw, err := MarshalJCS(DefaultCredentialContext())
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

// IssuerScope aliases registry.IssuerScope to share one canonical struct between credentials and ledger records.
type IssuerScope = registry.IssuerScope

// CredentialStatus identifies the on-chain status record for a verifiable credential.
type CredentialStatus struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// DomainAuthoritySubject models credentialSubject inside a DomainAuthorityCredential.
type DomainAuthoritySubject struct {
	ID              string        `json:"id"`
	DomainID        string        `json:"domainId"`
	IdentityIssuers []IssuerScope `json:"identityIssuers"`
}

// DomainAuthorityCredential models the JWT payload of a T-signed domain certification (typ="vc+jwt").
type DomainAuthorityCredential struct {
	Context           json.RawMessage        `json:"@context"`
	Type              []string               `json:"type"`
	ID                string                 `json:"id"`
	DeploymentID      string                 `json:"deploymentId"`
	Issuer            string                 `json:"issuer"`
	Iss               string                 `json:"iss"`
	Sub               string                 `json:"sub"`
	IssuerKeyVersion  uint64                 `json:"issuerKeyVersion"`
	ValidFrom         string                 `json:"validFrom"`
	ValidUntil        string                 `json:"validUntil"`
	NBF               int64                  `json:"nbf"`
	EXP               int64                  `json:"exp"`
	CredentialStatus  CredentialStatus       `json:"credentialStatus"`
	CredentialSubject DomainAuthoritySubject `json:"credentialSubject"`
}

// SignDomainAuthorityCredential canonicalizes, validates, and ES256-signs a DomainAuthorityCredential (typ="vc+jwt"),
// returning the raw compact JWS ASCII string and its SHA256(ASCII(compactJws)) hex digest.
func SignDomainAuthorityCredential(priv *ecdsa.PrivateKey, rootKeyID string, cred *DomainAuthorityCredential) (string, string, error) {
	if cred == nil {
		return "", "", NewError(ErrCodeInvalidSchema, "nil DomainAuthorityCredential")
	}
	ctxRaw, err := defaultCredentialContextRaw()
	if err != nil {
		return "", "", err
	}
	cred.Context = ctxRaw
	if err := cred.ValidateStructure(); err != nil {
		return "", "", err
	}
	payload, err := MarshalJCS(cred)
	if err != nil {
		return "", "", err
	}
	compact, err := SignCompactJWS(priv, TypeDomainAuthorityJWS, rootKeyID, payload)
	if err != nil {
		return "", "", err
	}
	return compact, DigestBytes([]byte(compact)), nil
}

// ParseAndVerifyDomainAuthorityCredential parses a compact JWS (typ="vc+jwt"), verifies its ES256 signature
// against T's root public key, and validates all grad-auth-v1 schema and identityIssuers constraints.
func ParseAndVerifyDomainAuthorityCredential(compact string, rootPub *ecdsa.PublicKey, wantRootKeyID string) (*DomainAuthorityCredential, string, error) {
	parsed, err := ParseCompactJWS(compact, TypeDomainAuthorityJWS)
	if err != nil {
		return nil, "", err
	}
	if err := verifyJWSWithKid(parsed, rootPub, wantRootKeyID); err != nil {
		return nil, "", err
	}
	return decodeAndValidateDomainAuthorityParsed(parsed)
}

func decodeAndValidateDomainAuthorityParsed(parsed *ParsedJWS) (*DomainAuthorityCredential, string, error) {
	var cred DomainAuthorityCredential
	if err := DecodeStrictJSON(parsed.PayloadBytes, &cred); err != nil {
		return nil, "", err
	}
	if err := cred.ValidateStructure(); err != nil {
		return nil, "", err
	}
	if cred.Issuer != "" && !strings.HasPrefix(parsed.Header.Kid, cred.Issuer+"#") {
		return nil, "", NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("JWS kid %q does not belong to issuer %q", parsed.Header.Kid, cred.Issuer))
	}
	return &cred, parsed.Digest, nil
}

// ValidateStructure verifies @context, type, timestamps, and lexicographically ordered identityIssuers.
func (c *DomainAuthorityCredential) ValidateStructure() error {
	if c == nil {
		return NewError(ErrCodeInvalidSchema, "nil DomainAuthorityCredential")
	}
	if err := ValidateCredentialContextRaw(c.Context); err != nil {
		return err
	}
	if len(c.Type) != 2 || c.Type[0] != CredentialTypeVC || c.Type[1] != CredentialTypeDomainAuthority {
		return NewError(ErrCodeInvalidSchema, "DomainAuthorityCredential type must equal [VerifiableCredential, DomainAuthorityCredential]")
	}
	if c.ID == "" || !IsHexDigest(c.DeploymentID, false) {
		return NewError(ErrCodeInvalidSchema, "DomainAuthorityCredential id and deploymentId required")
	}
	if !strings.HasPrefix(c.Issuer, "did:") || c.Iss != c.Issuer {
		return NewError(ErrCodeInvalidSchema, "DomainAuthorityCredential issuer and iss must match DID")
	}
	if !strings.HasPrefix(c.Sub, "did:") || c.CredentialSubject.ID != c.Sub {
		return NewError(ErrCodeInvalidSchema, "DomainAuthorityCredential sub must match credentialSubject.id")
	}
	if c.IssuerKeyVersion == 0 {
		return NewError(ErrCodeInvalidSchema, "DomainAuthorityCredential issuerKeyVersion must be >= 1")
	}
	if c.CredentialStatus.ID != c.ID || c.CredentialStatus.Type != StatusTypeDomainCertification {
		return NewError(ErrCodeInvalidSchema, "DomainAuthorityCredential credentialStatus invalid")
	}
	if err := validateTimestampPair(c.ValidFrom, c.ValidUntil, c.NBF, c.EXP); err != nil {
		return err
	}
	if c.CredentialSubject.DomainID == "" {
		return NewError(ErrCodeInvalidSchema, "DomainAuthorityCredential credentialSubject.domainId required")
	}
	issuers := c.CredentialSubject.IdentityIssuers
	if len(issuers) == 0 || len(issuers) > MaxIdentityIssuers {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("identityIssuers count %d must be in [1, %d]", len(issuers), MaxIdentityIssuers))
	}
	seenIssuer := make(map[string]struct{}, len(issuers))
	for i, sc := range issuers {
		if !strings.HasPrefix(sc.ID, "did:") {
			return NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("identityIssuers[%d].id %q must be a DID", i, sc.ID))
		}
		if _, dup := seenIssuer[sc.ID]; dup {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("duplicate identityIssuer %q", sc.ID))
		}
		seenIssuer[sc.ID] = struct{}{}
		if i > 0 && CompareUTF16(issuers[i-1].ID, sc.ID) >= 0 {
			return NewError(ErrCodeInvalidSchema, fmt.Sprintf("identityIssuers must be sorted ascending by id (%q >= %q)", issuers[i-1].ID, sc.ID))
		}
		if sc.AppKeyVersion == 0 {
			return NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("identityIssuers[%d].appKeyVersion must be >= 1", i))
		}
		if err := ValidateStringSet(sc.CredentialTypes, MaxIssuerTypesOrClaims); err != nil {
			return err
		}
		if err := ValidateStringSet(sc.ClaimNames, MaxIssuerTypesOrClaims); err != nil {
			return err
		}
	}
	return nil
}

// ConfirmationKey binds an SD-JWT credential holder to its EC public JWK.
type ConfirmationKey struct {
	JWK PublicKeyJWK `json:"jwk"`
}

// SDJWTCredentialSubject defines credentialSubject containing only id and sorted _sd digests.
type SDJWTCredentialSubject struct {
	ID string   `json:"id"`
	SD []string `json:"_sd"`
}

// EnterpriseIdentityCredential models the issuer-signed JWT claims for typ="vc+sd-jwt".
type EnterpriseIdentityCredential struct {
	Context           json.RawMessage        `json:"@context"`
	Type              []string               `json:"type"`
	ID                string                 `json:"id"`
	DeploymentID      string                 `json:"deploymentId"`
	Issuer            string                 `json:"issuer"`
	Iss               string                 `json:"iss"`
	Sub               string                 `json:"sub"`
	IssuerKeyVersion  uint64                 `json:"issuerKeyVersion"`
	AppKeyVersion     uint64                 `json:"appKeyVersion"`
	ValidFrom         string                 `json:"validFrom"`
	ValidUntil        string                 `json:"validUntil"`
	NBF               int64                  `json:"nbf"`
	EXP               int64                  `json:"exp"`
	CredentialStatus  CredentialStatus       `json:"credentialStatus"`
	Cnf               ConfirmationKey        `json:"cnf"`
	SDAlg             string                 `json:"_sd_alg"`
	CredentialSubject SDJWTCredentialSubject `json:"credentialSubject"`
}

// SignedSDJWTCredential wraps the issuer-signed compact JWT (for ledger anchor), disclosure strings,
// and combined SD-JWT with trailing '~' (suitable for ancestorCredentials or adding a KB-JWT).
type SignedSDJWTCredential struct {
	Claims             EnterpriseIdentityCredential
	IssuerSignedJWT    string
	AnchorDigest       string            // SHA256(ASCII(IssuerSignedJWT)), excluding disclosures and KB-JWT
	Disclosures        []string          // Base64url-encoded disclosures in canonical emission order
	DisclosureByClaim  map[string]string // claimName -> base64url disclosure
	PresentationPrefix string            // IssuerSignedJWT ~ d1 ~ d2 ~ (always ends with '~')
}

// DisclosureClaim represents one decoded RFC 9901 disclosure triple [salt, name, value].
type DisclosureClaim struct {
	RawDigest string
	Salt      string
	Name      string
	Value     string
}

// VerifiedIdentityCredential contains verified issuer JWT claims plus selectively disclosed attributes.
type VerifiedIdentityCredential struct {
	Claims        EnterpriseIdentityCredential
	AnchorDigest  string
	HolderPubHex  string
	HolderThumb   string
	Disclosed     map[string]string
	Domain        string
	Role          string
	HasKBJWT      bool
	KBJWT         string
	LeafPrefix    string // Up to and including final '~' before KBJWT
	DisclosureCnt int
}

// IssueEnterpriseIdentityCredential constructs salted disclosures (always domain, role, plus any optional extra string claims),
// sorts _sd digests lexicographically, ES256-signs the issuer JWT (typ="vc+sd-jwt"), and returns the anchored outputs.
func IssueEnterpriseIdentityCredential(
	priv *ecdsa.PrivateKey,
	issuerKeyID string,
	claims EnterpriseIdentityCredential,
	domainVal string,
	roleVal string,
	extraClaims map[string]string,
) (*SignedSDJWTCredential, error) {
	if domainVal == "" || roleVal == "" {
		return nil, NewError(ErrCodeInvalidSchema, "domain and role claim values must be non-empty")
	}
	ctxRaw, err := defaultCredentialContextRaw()
	if err != nil {
		return nil, err
	}
	claims.Context = ctxRaw
	claims.SDAlg = "sha-256"

	rawClaims := make(map[string]string, 2+len(extraClaims))
	for k, v := range extraClaims {
		if k == "" || k == "id" || k == "_sd" || v == "" {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid extra claim %q", k))
		}
		rawClaims[k] = v
	}
	rawClaims["domain"] = domainVal
	rawClaims["role"] = roleVal

	claimNames := make([]string, 0, len(rawClaims))
	for k := range rawClaims {
		claimNames = append(claimNames, k)
	}
	slices.Sort(claimNames)

	type sdEntry struct {
		digest     string
		claim      string
		disclosure string
	}
	entries := make([]sdEntry, 0, len(claimNames))
	for _, name := range claimNames {
		salt, err := randomSaltBase64URL(16)
		if err != nil {
			return nil, err
		}
		arrBytes, err := MarshalJCS([]string{salt, name, rawClaims[name]})
		if err != nil {
			return nil, err
		}
		disc := base64.RawURLEncoding.EncodeToString(arrBytes)
		entries = append(entries, sdEntry{
			digest:     DisclosureDigest(disc),
			claim:      name,
			disclosure: disc,
		})
	}
	slices.SortFunc(entries, func(a, b sdEntry) int {
		return strings.Compare(a.digest, b.digest)
	})

	sdDigests := make([]string, len(entries))
	disclosures := make([]string, len(entries))
	byClaim := make(map[string]string, len(entries))
	for i, e := range entries {
		sdDigests[i] = e.digest
		disclosures[i] = e.disclosure
		byClaim[e.claim] = e.disclosure
	}
	claims.CredentialSubject.SD = sdDigests

	if err := claims.ValidateStructure(); err != nil {
		return nil, err
	}
	payload, err := MarshalJCS(claims)
	if err != nil {
		return nil, err
	}
	issuerJWT, err := SignCompactJWS(priv, TypeSDJWT, issuerKeyID, payload)
	if err != nil {
		return nil, err
	}
	anchorDigest := DigestBytes([]byte(issuerJWT))
	prefix := issuerJWT + "~" + strings.Join(disclosures, "~") + "~"
	return &SignedSDJWTCredential{
		Claims:             claims,
		IssuerSignedJWT:    issuerJWT,
		AnchorDigest:       anchorDigest,
		Disclosures:        disclosures,
		DisclosureByClaim:  byClaim,
		PresentationPrefix: prefix,
	}, nil
}

// ValidateStructure verifies EnterpriseIdentityCredential payload schema, cnf.jwk, and sorted _sd digests.
func (c *EnterpriseIdentityCredential) ValidateStructure() error {
	if c == nil {
		return NewError(ErrCodeInvalidSchema, "nil EnterpriseIdentityCredential")
	}
	if err := ValidateCredentialContextRaw(c.Context); err != nil {
		return err
	}
	if len(c.Type) != 2 || c.Type[0] != CredentialTypeVC || c.Type[1] != CredentialTypeEnterpriseIdentity {
		return NewError(ErrCodeInvalidSchema, "EnterpriseIdentityCredential type must equal [VerifiableCredential, EnterpriseIdentityCredential]")
	}
	if c.ID == "" || !IsHexDigest(c.DeploymentID, false) {
		return NewError(ErrCodeInvalidSchema, "EnterpriseIdentityCredential id and deploymentId required")
	}
	if !strings.HasPrefix(c.Issuer, "did:") || c.Iss != c.Issuer {
		return NewError(ErrCodeInvalidSchema, "EnterpriseIdentityCredential issuer and iss must match DID")
	}
	if !strings.HasPrefix(c.Sub, "did:") || c.CredentialSubject.ID != c.Sub {
		return NewError(ErrCodeInvalidSchema, "EnterpriseIdentityCredential sub must match credentialSubject.id")
	}
	if c.IssuerKeyVersion == 0 || c.AppKeyVersion == 0 {
		return NewError(ErrCodeInvalidSchema, "issuerKeyVersion and appKeyVersion must be >= 1")
	}
	if c.CredentialStatus.ID != c.ID || c.CredentialStatus.Type != StatusTypeCredential {
		return NewError(ErrCodeInvalidSchema, "EnterpriseIdentityCredential credentialStatus invalid")
	}
	if err := validateTimestampPair(c.ValidFrom, c.ValidUntil, c.NBF, c.EXP); err != nil {
		return err
	}
	if _, err := PublicKeyFromJWK(c.Cnf.JWK); err != nil {
		return err
	}
	if c.SDAlg != "sha-256" {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("_sd_alg must be sha-256, got %q", c.SDAlg))
	}
	sd := c.CredentialSubject.SD
	if len(sd) < 2 {
		return NewError(ErrCodeInvalidDisclosure, "credentialSubject._sd must contain at least domain and role digests")
	}
	seen := make(map[string]struct{}, len(sd))
	for i, d := range sd {
		if _, err := DecodeStrictBase64URLFixed(d, 32); err != nil {
			return WrapError(ErrCodeInvalidDisclosure, fmt.Sprintf("invalid _sd digest at index %d", i), err)
		}
		if _, dup := seen[d]; dup {
			return NewError(ErrCodeInvalidDisclosure, fmt.Sprintf("duplicate _sd digest %q", d))
		}
		seen[d] = struct{}{}
		if i > 0 && strings.Compare(sd[i-1], d) >= 0 {
			return NewError(ErrCodeInvalidDisclosure, fmt.Sprintf("_sd digests not sorted lexicographically at index %d", i))
		}
	}
	return nil
}

// VerifySDJWTCredential parses an SD-JWT string (with or without KB-JWT, requiring trailing '~' or '~kbJwt'),
// verifies the issuer ES256 signature on the issuer-signed JWT, validates all disclosures against _sd without
// unused/duplicate disclosures or duplicate claim names, recovers mandatory domain/role claims, and computes
// AnchorDigest = SHA256(ASCII(issuerSignedJwt)).
func VerifySDJWTCredential(
	sdJWT string,
	issuerPub *ecdsa.PublicKey,
	wantIssuerKeyID string,
	expectedHolderPubHex string,
	requireKBJWT bool,
) (*VerifiedIdentityCredential, error) {
	issuerJWT, disclosures, kbJWT, err := splitAndCheckSDJWT(sdJWT, requireKBJWT)
	if err != nil {
		return nil, err
	}
	parsed, err := ParseCompactJWS(issuerJWT, TypeSDJWT)
	if err != nil {
		return nil, err
	}
	if err := verifyJWSWithKid(parsed, issuerPub, wantIssuerKeyID); err != nil {
		return nil, err
	}
	return verifySDJWTPayloadAndDisclosures(sdJWT, parsed, disclosures, kbJWT, expectedHolderPubHex)
}

func splitAndCheckSDJWT(sdJWT string, requireKBJWT bool) (string, []string, string, error) {
	if sdJWT == "" || len(sdJWT) > MaxJSONBytes {
		return "", nil, "", NewError(ErrCodeInvalidSchema, "SD-JWT empty or exceeds max length")
	}
	for i := 0; i < len(sdJWT); i++ {
		if sdJWT[i] > 0x7F {
			return "", nil, "", NewError(ErrCodeInvalidSchema, "SD-JWT contains non-ASCII character")
		}
	}
	if !strings.ContainsRune(sdJWT, '~') {
		return "", nil, "", NewError(ErrCodeInvalidDisclosure, "SD-JWT presentation must contain '~' separator and disclosures")
	}
	parts := strings.Split(sdJWT, "~")
	if len(parts) < 3 {
		return "", nil, "", NewError(ErrCodeInvalidDisclosure, "SD-JWT presentation must contain issuer JWT, disclosures, and final KB slot")
	}
	issuerJWT := parts[0]
	kbJWT := parts[len(parts)-1]
	disclosures := parts[1 : len(parts)-1]

	if requireKBJWT && kbJWT == "" {
		return "", nil, "", NewError(ErrCodeInvalidSchema, "leaf SD-JWT presentation must include KB-JWT")
	}
	if !requireKBJWT && kbJWT != "" {
		return "", nil, "", NewError(ErrCodeInvalidSchema, "ancestor credential presentation must end with '~' without KB-JWT")
	}
	return issuerJWT, disclosures, kbJWT, nil
}

func verifySDJWTPayloadAndDisclosures(
	sdJWT string,
	parsed *ParsedJWS,
	disclosures []string,
	kbJWT string,
	expectedHolderPubHex string,
) (*VerifiedIdentityCredential, error) {
	var claims EnterpriseIdentityCredential
	if err := DecodeStrictJSON(parsed.PayloadBytes, &claims); err != nil {
		return nil, err
	}
	if err := claims.ValidateStructure(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(parsed.Header.Kid, claims.Issuer+"#") {
		return nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("JWS kid %q does not belong to issuer %q", parsed.Header.Kid, claims.Issuer))
	}

	cnfPub, err := PublicKeyFromJWK(claims.Cnf.JWK)
	if err != nil {
		return nil, err
	}
	cnfPubHex, err := FormatAppPublicKey(cnfPub)
	if err != nil {
		return nil, err
	}
	thumb, err := JWKThumbprint(claims.Cnf.JWK)
	if err != nil {
		return nil, err
	}
	if expectedHolderPubHex != "" && cnfPubHex != expectedHolderPubHex {
		return nil, NewError(ErrCodeHolderMismatch, "SD-JWT cnf.jwk mismatches registered holder appPublicKey")
	}

	sdSet := make(map[string]struct{}, len(claims.CredentialSubject.SD))
	for _, d := range claims.CredentialSubject.SD {
		sdSet[d] = struct{}{}
	}
	usedDigests := make(map[string]struct{}, len(disclosures))
	seenDisclosures := make(map[string]struct{}, len(disclosures))
	disclosed := make(map[string]string, len(disclosures))

	for i, disc := range disclosures {
		if disc == "" {
			return nil, NewError(ErrCodeInvalidDisclosure, fmt.Sprintf("empty disclosure at index %d", i))
		}
		if _, dupRaw := seenDisclosures[disc]; dupRaw {
			return nil, NewError(ErrCodeInvalidDisclosure, fmt.Sprintf("duplicate disclosure string at index %d", i))
		}
		seenDisclosures[disc] = struct{}{}

		digest := DisclosureDigest(disc)
		if _, inSD := sdSet[digest]; !inSD {
			return nil, NewError(ErrCodeInvalidDisclosure, fmt.Sprintf("unreferenced disclosure digest %q not in credentialSubject._sd", digest))
		}
		if _, dupDigest := usedDigests[digest]; dupDigest {
			return nil, NewError(ErrCodeInvalidDisclosure, fmt.Sprintf("duplicate disclosure targeting digest %q", digest))
		}
		usedDigests[digest] = struct{}{}

		rawJSON, err := DecodeStrictBase64URL(disc)
		if err != nil {
			return nil, WrapError(ErrCodeInvalidDisclosure, fmt.Sprintf("decode disclosure[%d]", i), err)
		}
		var triple []string
		if err := DecodeStrictJSON(rawJSON, &triple); err != nil {
			return nil, WrapError(ErrCodeInvalidDisclosure, fmt.Sprintf("parse disclosure[%d] JSON", i), err)
		}
		if len(triple) != 3 || triple[0] == "" || triple[1] == "" || triple[2] == "" {
			return nil, NewError(ErrCodeInvalidDisclosure, fmt.Sprintf("disclosure[%d] must be 3 non-empty strings [salt, claimName, claimValue]", i))
		}
		claimName := triple[1]
		claimVal := triple[2]
		if claimName == "id" || claimName == "_sd" {
			return nil, NewError(ErrCodeInvalidDisclosure, fmt.Sprintf("illegal selective disclosure claim name %q", claimName))
		}
		if _, dupClaim := disclosed[claimName]; dupClaim {
			return nil, NewError(ErrCodeInvalidDisclosure, fmt.Sprintf("duplicate disclosed claim name %q", claimName))
		}
		disclosed[claimName] = claimVal
	}

	domain, okDomain := disclosed["domain"]
	role, okRole := disclosed["role"]
	if !okDomain || domain == "" || !okRole || role == "" {
		return nil, NewError(ErrCodeInvalidDisclosure, "missing mandatory disclosed claims domain and/or role")
	}

	lastTilde := strings.LastIndexByte(sdJWT, '~')
	leafPrefix := sdJWT[:lastTilde+1]

	return &VerifiedIdentityCredential{
		Claims:        claims,
		AnchorDigest:  parsed.Digest,
		HolderPubHex:  cnfPubHex,
		HolderThumb:   thumb,
		Disclosed:     disclosed,
		Domain:        domain,
		Role:          role,
		HasKBJWT:      kbJWT != "",
		KBJWT:         kbJWT,
		LeafPrefix:    leafPrefix,
		DisclosureCnt: len(disclosures),
	}, nil
}

// DisclosureDigest computes base64url(SHA256(ASCII(disclosure))) per RFC 9901.
func DisclosureDigest(disclosure string) string {
	sum := sha256.Sum256([]byte(disclosure))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomSaltBase64URL(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validateTimestampPair(validFrom, validUntil string, nbf, exp int64) error {
	vf, err := time.Parse(time.RFC3339, validFrom)
	if err != nil || vf.UTC().Format(time.RFC3339) != validFrom {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("validFrom %q must be RFC3339 UTC whole seconds", validFrom))
	}
	vu, err := time.Parse(time.RFC3339, validUntil)
	if err != nil || vu.UTC().Format(time.RFC3339) != validUntil {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("validUntil %q must be RFC3339 UTC whole seconds", validUntil))
	}
	if nbf <= 0 || exp <= nbf || exp > registry.MaxUnixTimestamp {
		return NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid time window nbf=%d exp=%d", nbf, exp))
	}
	if vf.Unix() != nbf || vu.Unix() != exp {
		return NewError(ErrCodeInvalidSchema, "validFrom/validUntil must match Unix seconds nbf/exp")
	}
	return nil
}

// DomainAnchorState summarizes on-chain RootRecord/Domain/Certification fields checked against DomainAuthorityCredential.
type DomainAnchorState struct {
	RootDID            string
	RootKeyVersion     uint64
	DomainID           string
	DomainDID          string
	DomainIssuers      []string
	CertificationID    string
	CertificationNBF   int64
	CertificationEXP   int64
	CertificationDig   string
	CertificationScope []IssuerScope
}

// VerifyAgainstChain checks consistency between a signed DomainAuthorityCredential and ledger records.
func (c *DomainAuthorityCredential) VerifyAgainstChain(digest string, state DomainAnchorState) error {
	if err := c.ValidateStructure(); err != nil {
		return err
	}
	if digest == "" || digest != state.CertificationDig {
		return NewError(ErrCodeDomainCertificationInvalid, "domain certification digest mismatches on-chain Certification.digest")
	}
	if c.DeploymentID == "" {
		return NewError(ErrCodeInvalidSchema, "missing deploymentId")
	}
	if c.ID != state.CertificationID {
		return NewError(ErrCodeDomainCertificationInvalid, fmt.Sprintf("certificationId %q != %q", c.ID, state.CertificationID))
	}
	if c.Issuer != state.RootDID || c.IssuerKeyVersion != state.RootKeyVersion {
		return NewError(ErrCodeDomainCertificationInvalid, "domain certification issuer or issuerKeyVersion mismatches RootRecord")
	}
	if c.CredentialSubject.DomainID != state.DomainID || c.CredentialSubject.ID != state.DomainDID {
		return NewError(ErrCodeDomainCertificationInvalid, "domain certification subject mismatches DomainRecord")
	}
	if c.NBF != state.CertificationNBF || c.EXP != state.CertificationEXP {
		return NewError(ErrCodeDomainCertificationInvalid, "domain certification nbf/exp mismatches on-chain Certification interval")
	}
	if !issuerScopesEqual(c.CredentialSubject.IdentityIssuers, state.CertificationScope) {
		return NewError(ErrCodeIssuerScopeInvalid, "domain certification identityIssuers mismatch on-chain Certification scopes")
	}
	if len(state.DomainIssuers) > 0 {
		domainSet := make(map[string]struct{}, len(state.DomainIssuers))
		for _, id := range state.DomainIssuers {
			domainSet[id] = struct{}{}
		}
		for _, sc := range c.CredentialSubject.IdentityIssuers {
			if _, ok := domainSet[sc.ID]; !ok {
				return NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("certified issuer %q not registered on DomainRecord.identityIssuers", sc.ID))
			}
		}
	}
	return nil
}

// FindIssuerScope verifies that issuerDID is authorized inside DomainAuthorityCredential for the
// given issuerKeyVersion, credentialType, and every disclosed claim name.
func (c *DomainAuthorityCredential) FindIssuerScope(issuerDID string, issuerKeyVersion uint64, credType string, claimNames []string) (*IssuerScope, error) {
	for i := range c.CredentialSubject.IdentityIssuers {
		sc := &c.CredentialSubject.IdentityIssuers[i]
		if sc.ID != issuerDID {
			continue
		}
		if sc.AppKeyVersion != issuerKeyVersion {
			return nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("issuer %q keyVersion %d mismatches certified %d", issuerDID, issuerKeyVersion, sc.AppKeyVersion))
		}
		if !slices.Contains(sc.CredentialTypes, credType) {
			return nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("issuer %q not authorized for credential type %q", issuerDID, credType))
		}
		for _, name := range claimNames {
			if !slices.Contains(sc.ClaimNames, name) {
				return nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("issuer %q not authorized to issue claim %q", issuerDID, name))
			}
		}
		return sc, nil
	}
	return nil, NewError(ErrCodeIssuerScopeInvalid, fmt.Sprintf("issuer %q not in domain certification identityIssuers", issuerDID))
}

func issuerScopesEqual(a, b []IssuerScope) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].AppKeyVersion != b[i].AppKeyVersion ||
			!slices.Equal(a[i].CredentialTypes, b[i].CredentialTypes) ||
			!slices.Equal(a[i].ClaimNames, b[i].ClaimNames) {
			return false
		}
	}
	return true
}

func verifyJWSWithKid(parsed *ParsedJWS, pub *ecdsa.PublicKey, wantKid string) error {
	if wantKid != "" && parsed.Header.Kid != wantKid {
		return NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("JWS kid %q mismatches expected %q", parsed.Header.Kid, wantKid))
	}
	return parsed.Verify(pub)
}
