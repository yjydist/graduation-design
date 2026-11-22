package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"grad/platform/gateway"
	"grad/platform/state/fabric"
	"grad/protocol"
	"grad/protocol/registry"
)

func (e *e1Trial) bootstrap() error {
	check, err := e.refresh(e.ctx, e.f.RPG2.ID)
	if err != nil {
		return err
	}
	var actual registry.Bootstrap
	if err := json.Unmarshal(check.Records[registry.BootstrapKey], &actual); err != nil {
		return err
	}
	if actual != e.d.Bootstrap || check.DeploymentID != e.d.DeploymentID {
		return fmt.Errorf("applied bootstrap differs from the fixed deployment manifest")
	}
	domains := map[string]any{}
	for _, id := range []string{"A", "B", "C"} {
		op := e.seedOperation("domain-" + id)
		if op == nil || op.Commit == nil || op.Commit.Code != "VALID" {
			return fmt.Errorf("missing valid bootstrap commit for %s", id)
		}
		beforeRaw, err := e.rawAt("domain", id, op.Commit.Number)
		if err != nil {
			return err
		}
		var before registry.Domain
		if err := json.Unmarshal(beforeRaw, &before); err != nil {
			return err
		}
		after, err := currentRecord[registry.Domain](e, "domain", id)
		if err != nil {
			return err
		}
		if before.Status != registry.Pending || after.Status != registry.Active || after.Certification == "" ||
			(id == "A" && after.PurchasingAuthority != e.f.Identities["PA"].ID) {
			return fmt.Errorf("incorrect pending or active state for %s", id)
		}
		domains[id] = map[string]any{"pending": before, "active": after, "pendingBlock": op.Commit.Number}
	}
	return e.save("F01", map[string]any{"root": actual.Root, "domains": domains, "checkpoint": check.Point, "manifest": e.d.Raw})
}

func (e *e1Trial) checkLinkedAccountIsolation() error {
	mode := e.modes[0]
	account := e.f.Identities["U-in-B"]
	key, err := fabric.LoadECPrivateKeyPEM(e.inst.PrivatePath("app", "U-in-B.key.pem"))
	if err != nil {
		return err
	}
	read := func(parts ...string) (string, error) {
		raw, err := os.ReadFile(e.inst.RegistryPath(parts...))
		return string(raw), err
	}
	pres, err := read("credentials", "U-in-B.sdjwt")
	if err != nil {
		return err
	}
	service, err := read("credentials", "C.sdjwt")
	if err != nil {
		return err
	}
	grant, err := read("grants", "rp_g0.jws")
	if err != nil {
		return err
	}
	var paths []protocol.TrustPathEntry
	for _, id := range []string{"B", "C"} {
		jws, err := read("certifications", id+".jws")
		if err != nil {
			return err
		}
		paths = append(paths, protocol.TrustPathEntry{Issuer: e.f.Domains[id].Issuers[0].ID, DomainCertification: jws})
	}
	req := protocol.AccessRequest{
		SchemaVersion: registry.Schema, DeploymentID: e.d.DeploymentID, Actor: account.ID, PrincipalDomain: "A",
		AuthorizationMode: registry.RP, TaskID: mode.task.ID, Audience: "https://c.local", Resource: registry.ResourceQuotes,
		Action: registry.ActionQuoteRead, SupplierID: gateway.DefaultSupplierID, ProductID: gateway.DefaultProductID,
		Quantity: 1, Currency: gateway.DefaultCurrency, IdempotencyKey: "e1-linked-account",
	}
	if _, err := e.ensureTaskContextNormal(e.server.Handler(), mode.task.ID, time.Now().Unix()); err != nil {
		return err
	}
	handler := e.observe(mode, e.server.Handler())
	pkg, _, err := e.buildLeafExecutePackage(handler, req, e.f.ProcurementTaskSpec, key, account.KeyID, pres,
		[]protocol.AncestorCredential{{CredentialID: mode.g0.IssuerCredential, Presentation: service}}, []string{grant}, paths, time.Now().Unix())
	if err != nil {
		return err
	}
	resp := gatewayPostExecute(handler, pkg)
	var denied gateway.ErrorBody
	_ = json.Unmarshal(resp.Body.Bytes(), &denied)
	if err := e.save("F02-isolation", map[string]any{"actor": account.ID, "status": resp.Code, "code": denied.Code}); err != nil {
		return err
	}
	if resp.Code != http.StatusUnauthorized || denied.Code != protocol.ErrCodeHolderMismatch {
		return fmt.Errorf("linked identity exercised another account's path: HTTP %d %s", resp.Code, denied.Code)
	}
	return nil
}

func (e *e1Trial) trust() error {
	root := e.d.Bootstrap.Root
	rootPub, err := protocol.ParseAppPublicKey(root.PublicKey)
	if err != nil {
		return err
	}
	evidence := map[string]any{}
	for _, name := range []string{"A", "B", "C"} {
		domain, err := currentRecord[registry.Domain](e, "domain", name)
		if err != nil {
			return err
		}
		anchor, err := currentRecord[registry.Certification](e, "certification", domain.Certification)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(e.inst.RegistryPath("certifications", name+".jws"))
		if err != nil {
			return err
		}
		cert, digest, err := protocol.ParseAndVerifyDomainAuthorityCredential(string(raw), rootPub, root.KeyID)
		if err != nil {
			return err
		}
		if domain.Status != registry.Active || anchor.Status != registry.Active || !anchor.Interval.Current(time.Now(), 0) {
			return fmt.Errorf("inactive trust path for %s", name)
		}
		if err := cert.VerifyAgainstChain(digest, protocol.DomainAnchorState{
			RootDID: root.DID, RootKeyVersion: root.KeyVersion,
			DomainID: name, DomainDID: domain.DID, DomainIssuers: domain.Issuers,
			CertificationID: anchor.ID, CertificationNBF: anchor.NBF,
			CertificationEXP: anchor.EXP, CertificationDig: anchor.Digest, CertificationScope: anchor.Scopes,
		}); err != nil {
			return err
		}
		evidence[name] = map[string]any{"certification": anchor, "verifiedJWS": string(raw)}
	}
	for _, role := range []string{"PA", "U", "A1", "B1", "C"} {
		if err := e.verifyIdentityCredential(role, e.f.Identities[role]); err != nil {
			return err
		}
	}
	ia := e.f.Domains["A"].Issuers[0]
	_, _, _, purposeErr := e.resolver.ResolveDID(e.ctx, ia.ID, protocol.DIDResolutionExpectation{
		ExpectedDigest: ia.DocumentDigest, ExpectedKeyID: ia.KeyID, ExpectedKeyVersion: ia.KeyVersion,
		ExpectedPublicKeyHex: ia.PublicKey, RequiredPurpose: protocol.KeyPurposeAuthentication,
	})
	if !protocol.HasCode(purposeErr, protocol.ErrCodeDIDKeyPurposeInvalid) {
		return fmt.Errorf("assertion-only issuer key returned %v", purposeErr)
	}
	evidence["wrongKeyPurpose"] = fmt.Sprint(purposeErr)
	return e.save("F04", evidence)
}

func (e *e1Trial) verifyIdentityCredential(role string, id registry.Identity) error {
	anchor, err := currentRecord[registry.Credential](e, "credential", e.f.Credentials[role].ID)
	if err != nil {
		return err
	}
	issuer, err := currentRecord[registry.Identity](e, "identity", anchor.Issuer)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(e.inst.RegistryPath("credentials", role+".sdjwt"))
	if err != nil {
		return err
	}
	_, pub, _, err := e.resolver.ResolveDID(e.ctx, issuer.ID, protocol.DIDResolutionExpectation{
		ExpectedDigest: issuer.DocumentDigest, ExpectedKeyID: issuer.KeyID,
		ExpectedKeyVersion: issuer.KeyVersion, ExpectedPublicKeyHex: issuer.PublicKey, RequiredPurpose: protocol.KeyPurposeAssertionMethod,
	})
	if err != nil {
		return err
	}
	_, _, _, err = e.resolver.ResolveDID(e.ctx, id.ID, protocol.DIDResolutionExpectation{
		ExpectedDigest: id.DocumentDigest, ExpectedKeyID: id.KeyID,
		ExpectedKeyVersion: id.KeyVersion, ExpectedPublicKeyHex: id.PublicKey, RequiredPurpose: protocol.KeyPurposeAuthentication,
	})
	if err != nil {
		return err
	}
	cred, err := protocol.VerifySDJWTCredential(string(raw), pub, issuer.KeyID, id.PublicKey, false)
	if err != nil {
		return err
	}
	expectedRole := ""
	if role == "C" {
		expectedRole = "supplier-service"
	}
	domain, err := currentRecord[registry.Domain](e, "domain", id.Domain)
	if err != nil {
		return err
	}
	cert, err := currentRecord[registry.Certification](e, "certification", domain.Certification)
	if err != nil {
		return err
	}
	if anchor.Status != registry.Active || anchor.Digest != cred.AnchorDigest || cred.Domain != id.Domain || issuer.Domain != id.Domain ||
		(expectedRole != "" && cred.Role != expectedRole) || !slices.ContainsFunc(cert.Scopes, func(scope registry.IssuerScope) bool {
		return scope.ID == issuer.ID && scope.AppKeyVersion == anchor.IssuerKeyVersion && slices.Contains(scope.CredentialTypes, anchor.Type)
	}) {
		return fmt.Errorf("%s credential differs from the committed trust path", role)
	}
	return nil
}
