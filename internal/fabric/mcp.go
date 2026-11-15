package fabric

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"graduation-design/internal/agent"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
	"graduation-design/internal/serviceauth"
)

func runMCPCmd(ctx context.Context, i *instance, d deployment, db *pgxpool.Pool, gatewayURL string) error {
	if strings.TrimSpace(gatewayURL) == "" {
		gatewayURL = os.Getenv("GATEWAY_URL")
	}
	if strings.TrimSpace(gatewayURL) == "" {
		gatewayURL = "http://127.0.0.1:8103"
	}
	f, err := i.fixtures(&d)
	if err != nil {
		return err
	}
	w, err := buildM2WalletContext(ctx, i, d, f, db, gatewayURL, nil, nil)
	if err != nil {
		return err
	}
	srv := agent.NewMCPServer(w)
	return srv.Run(ctx, &mcp.StdioTransport{})
}

func buildM2WalletContext(
	ctx context.Context,
	i *instance,
	d deployment,
	f *fixtures,
	db *pgxpool.Pool,
	gatewayURL string,
	httpHandler http.Handler,
	nowFn func() time.Time,
) (*agent.WalletContext, error) {
	if f == nil {
		var err error
		f, err = i.fixtures(&d)
		if err != nil {
			return nil, err
		}
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	certA, err := os.ReadFile(i.registrySubPath("certifications", "A.jws"))
	if err != nil {
		return nil, err
	}
	certB, err := os.ReadFile(i.registrySubPath("certifications", "B.jws"))
	if err != nil {
		return nil, err
	}
	certC, err := os.ReadFile(i.registrySubPath("certifications", "C.jws"))
	if err != nil {
		return nil, err
	}
	cSvcSD, err := os.ReadFile(i.registrySubPath("credentials", "C-service.sdjwt"))
	if err != nil {
		cSvcSD, err = os.ReadFile(i.registrySubPath("credentials", "C.sdjwt"))
		if err != nil {
			return nil, err
		}
	}
	paSD, err := os.ReadFile(i.registrySubPath("credentials", "PA.sdjwt"))
	if err != nil {
		return nil, err
	}
	uSD, err := os.ReadFile(i.registrySubPath("credentials", "U.sdjwt"))
	if err != nil {
		return nil, err
	}
	a1SD, err := os.ReadFile(i.registrySubPath("credentials", "A1.sdjwt"))
	if err != nil {
		return nil, err
	}

	cIssuerDID := f.Domains["C"].Issuers[0].ID
	bIssuerDID := f.Domains["B"].Issuers[0].ID
	aIssuerDID := f.Domains["A"].Issuers[0].ID
	tpCSingle := []protocol.TrustPathEntry{
		{Issuer: cIssuerDID, DomainCertification: string(certC)},
	}
	tpASingle := []protocol.TrustPathEntry{
		{Issuer: aIssuerDID, DomainCertification: string(certA)},
	}
	tpAC := []protocol.TrustPathEntry{
		{Issuer: aIssuerDID, DomainCertification: string(certA)},
		{Issuer: cIssuerDID, DomainCertification: string(certC)},
	}
	tpAB := []protocol.TrustPathEntry{
		{Issuer: aIssuerDID, DomainCertification: string(certA)},
		{Issuer: bIssuerDID, DomainCertification: string(certB)},
	}
	tpABC := []protocol.TrustPathEntry{
		{Issuer: aIssuerDID, DomainCertification: string(certA)},
		{Issuer: bIssuerDID, DomainCertification: string(certB)},
		{Issuer: cIssuerDID, DomainCertification: string(certC)},
	}

	trustPathsForMode := func(mode string) []protocol.TrustPathEntry {
		if mode == api.RP {
			return tpABC
		}
		return tpAB
	}
	buildChainGrant := func(claims protocol.GrantClaims, digest, parentOverride string) api.Grant {
		parentID, parentDigest := parentOverride, ""
		if claims.ParentID != nil && *claims.ParentID != "" {
			parentID = *claims.ParentID
		}
		if claims.ParentDigest != nil {
			parentDigest = *claims.ParentDigest
		}
		return api.Grant{
			Bound:             api.Bound{DeploymentID: d.DeploymentID},
			ID:                claims.ID,
			Schema:            api.Schema,
			Parent:            parentID,
			ParentDigest:      parentDigest,
			Root:              claims.RootID,
			Task:              claims.TaskID,
			Mode:              claims.AuthorizationMode,
			Domain:            claims.PrincipalDomain,
			Resource:          claims.ResourceID,
			Issuer:            claims.Issuer,
			Grantee:           claims.Grantee,
			IssuerKeyVersion:  claims.IssuerKeyVersion,
			GranteeKeyVersion: claims.GranteeKeyVersion,
			IssuerCredential:  claims.IssuerCredentialID,
			GranteeCredential: claims.GranteeCredentialID,
			Depth:             uint8(claims.RemainingDepth),
			Digest:            digest,
			Interval:          api.Interval{NBF: claims.NBF, EXP: claims.EXP},
		}
	}

	var anchorFn func(context.Context, agent.AnchorChildGrantRequest) (*agent.AnchorChildGrantResult, error)
	var replaceFn func(context.Context, agent.ReplaceGrantRequest) (*agent.ReplaceGrantResult, error)
	if i != nil && db != nil {
		if err := initSchema(ctx, db, operationsSchema); err != nil {
			return nil, err
		}
		j := journal{instance: i, deploymentID: d.DeploymentID, db: db}
		anchorFn = func(callCtx context.Context, req agent.AnchorChildGrantRequest) (*agent.AnchorChildGrantResult, error) {
			chainGrant := buildChainGrant(req.Claims, req.GrantDigest, req.ParentID)
			opKey := "mcp-anchor/" + api.Digest([]byte(req.Claims.ID))[:24]
			op, err := j.write(callCtx, opKey, req.IssuerActor, "RegisterGrant", payload(chainGrant))
			if err != nil {
				return nil, err
			}
			if err := expectOperation(op, "VALID"); err != nil {
				return nil, err
			}
			return &agent.AnchorChildGrantResult{
				Anchored:   true,
				TrustPaths: trustPathsForMode(req.Claims.AuthorizationMode),
			}, nil
		}
		replaceFn = func(callCtx context.Context, req agent.ReplaceGrantRequest) (*agent.ReplaceGrantResult, error) {
			rev := req.OldGrantRevision
			if rev == 0 {
				rev = 1
			}
			oldMut := api.Mutation{
				Bound:            api.Bound{DeploymentID: d.DeploymentID},
				ID:               req.OldGrantID,
				ExpectedRevision: rev,
				ExpectedDigest:   req.OldGrantDigest,
			}
			chainGrant := buildChainGrant(req.NewClaims, req.NewGrantDigest, "")
			opKey := "mcp-replace/" + api.Digest([]byte(req.OldGrantID + "/" + req.NewClaims.ID))[:24]
			op, err := j.write(callCtx, opKey, req.IssuerActor, "ReplaceGrant", payload(api.Replacement{
				Old: oldMut,
				New: chainGrant,
			}))
			if err != nil {
				return nil, err
			}
			if err := expectOperation(op, "VALID"); err != nil {
				return nil, err
			}
			return &agent.ReplaceGrantResult{
				Anchored:   true,
				TrustPaths: trustPathsForMode(req.NewClaims.AuthorizationMode),
			}, nil
		}
	}

 var recoveryClient,auditClient,receiptClient *http.Client
 if httpHandler!=nil {
 recoveryClient=serviceauth.NewLocalClient(httpHandler,serviceauth.Identity{Role:"B_RECOVERY",DID:"did:web:b.local:services:recovery"})
 auditClient=serviceauth.NewLocalClient(httpHandler,serviceauth.Identity{Role:"C_AUDITOR",DID:"did:web:c.local:auditors:c1"})
 receiptClient=serviceauth.NewLocalClient(httpHandler,serviceauth.Identity{Role:"C_AUDIT_SERVICE",DID:"did:web:c.local:services:audit"})
 } else {
 load:=func(prefix string)(*http.Client,error){cert,key,ca:=os.Getenv(prefix+"_MTLS_CERT"),os.Getenv(prefix+"_MTLS_KEY"),os.Getenv(prefix+"_MTLS_CA");if cert==""&&key==""&&ca==""{return nil,nil};return serviceauth.NewMTLSClient(cert,key,ca)}
 var err error
 recoveryClient,err=load("RECOVERY");if err!=nil{return nil,err};auditClient,err=load("AUDIT");if err!=nil{return nil,err};receiptClient,err=load("RECEIPT");if err!=nil{return nil,err}
 }
	var receiptDelivery func(context.Context, gateway.OrderOutcomeReceipt) (*gateway.OrderOutcomeReceiptResponse, error)
	if httpHandler != nil {
		receiptDelivery = func(ctx context.Context, r gateway.OrderOutcomeReceipt) (*gateway.OrderOutcomeReceiptResponse, error) {
			return gateway.DeliverStoredReceipt(ctx, db, d.DeploymentID, serviceauth.NewLocalClient(httpHandler, serviceauth.Identity{Role: "C_AUDIT_SERVICE", DID: "did:web:c.local:auditors:c1"}), "https://c.local/v1/internal/order-outcome-receipts", r)
		}
	}
	w, err := agent.NewWalletContext(agent.WalletConfig{
		ReceiptDelivery:  receiptDelivery,
		DeploymentID:     d.DeploymentID,
		GatewayURL:       gatewayURL,
		Audience:         "https://c.local",
		SupplierID:       "urn:grad:supplier:C",
		SupplierDID:      f.Identities["C"].ID,
		DefaultTaskSpec:  f.M2TaskSpec,
		Currency:         "CNY",
		AuditorDID:       "did:web:c.local:auditors:c1",
		RecoveryDID:      "did:web:b.local:services:recovery",
		DB:               db,
		HTTPHandler:      httpHandler,
		RecoveryClient: recoveryClient,
		AuditClient: auditClient,
		ReceiptClient: receiptClient,
		Now:              nowFn,
		AnchorChildFunc:  anchorFn,
		ReplaceGrantFunc: replaceFn,
	})
	if err != nil {
		return nil, err
	}
	if db != nil {
		_ = gateway.EnsureSchema(ctx, db, d.DeploymentID, "urn:grad:supplier:C")
	}

	roleOrder := []string{"U", "A1", "B1", "B2", "U-in-B", "PA"}
	for _, role := range roleOrder {
		id, ok := f.Identities[role]
		if !ok {
			continue
		}
		priv, err := loadECPrivateKeyPEM(i.privatePath("app", role+".key.pem"))
		if err != nil {
			return nil, fmt.Errorf("load %s private key: %w", role, err)
		}
		sdBytes, err := os.ReadFile(i.registrySubPath("credentials", role+".sdjwt"))
		if err != nil {
			return nil, fmt.Errorf("load %s SD-JWT: %w", role, err)
		}
		credID := "cred:" + role
		if c, ok := f.Credentials[role]; ok && c.ID != "" {
			credID = c.ID
		}
		if err := w.RegisterActor(agent.ActorConfig{
			Actor:             role,
			DID:               id.ID,
			KeyID:             id.KeyID,
			CredentialID:      credID,
			KeyVersion:        id.KeyVersion,
			DomainID:          id.Domain,
			EntityType:        id.Kind,
			Roles:             []string{id.Kind},
			PrivateKey:        priv,
			SDJWTPresentation: string(sdBytes),
		}); err != nil {
			return nil, fmt.Errorf("register actor %s: %w", role, err)
		}
	}

	cCredID := f.Credentials["C"].ID
	if cSvc, ok := f.Credentials["C-service"]; ok && cSvc.ID != "" {
		cCredID = cSvc.ID
	}
	if cCredID == "" {
		cCredID = "cred:C"
	}
	paCredID := f.Credentials["PA"].ID
	if paCredID == "" {
		paCredID = "cred:PA"
	}
	uCredID := f.Credentials["U"].ID
	if uCredID == "" {
		uCredID = "cred:U"
	}
	a1CredID := f.Credentials["A1"].ID
	if a1CredID == "" {
		a1CredID = "cred:A1"
	}

	addChain := func(rootFile, g1File, g2File string, rootAnc protocol.AncestorCredential, rootTP, g1TP, g2TP []protocol.TrustPathEntry) error {
		g0Raw, err := os.ReadFile(i.registrySubPath("grants", rootFile))
		if err != nil {
			return err
		}
		g1Raw, err := os.ReadFile(i.registrySubPath("grants", g1File))
		if err != nil {
			return err
		}
		g0Claims, err := decodeGrantPayload(string(g0Raw))
		if err != nil {
			return err
		}
		g1Claims, err := decodeGrantPayload(string(g1Raw))
		if err != nil {
			return err
		}
		if err := w.AddGrantBundle(agent.GrantBundle{
			Claims:              g0Claims,
			TaskSpec:            f.M2TaskSpec,
			RawGrantJWS:         string(g0Raw),
			ChainRawGrants:      []string{string(g0Raw)},
			AncestorCredentials: []protocol.AncestorCredential{rootAnc},
			TrustPaths:          rootTP,
			Anchored:            true,
		}); err != nil {
			return err
		}
		if err := w.AddGrantBundle(agent.GrantBundle{
			Claims:         g1Claims,
			TaskSpec:       f.M2TaskSpec,
			RawGrantJWS:    string(g1Raw),
			ChainRawGrants: []string{string(g0Raw), string(g1Raw)},
			AncestorCredentials: []protocol.AncestorCredential{
				rootAnc,
				{CredentialID: uCredID, Presentation: string(uSD)},
			},
			TrustPaths: g1TP,
			Anchored:   true,
		}); err != nil {
			return err
		}
		if g2File != "" {
			g2Raw, err := os.ReadFile(i.registrySubPath("grants", g2File))
			if err != nil {
				return err
			}
			g2Claims, err := decodeGrantPayload(string(g2Raw))
			if err != nil {
				return err
			}
			if err := w.AddGrantBundle(agent.GrantBundle{
				Claims:         g2Claims,
				TaskSpec:       f.M2TaskSpec,
				RawGrantJWS:    string(g2Raw),
				ChainRawGrants: []string{string(g0Raw), string(g1Raw), string(g2Raw)},
				AncestorCredentials: []protocol.AncestorCredential{
					rootAnc,
					{CredentialID: uCredID, Presentation: string(uSD)},
					{CredentialID: a1CredID, Presentation: string(a1SD)},
				},
				TrustPaths: g2TP,
				Anchored:   true,
			}); err != nil {
				return err
			}
		}
		return nil
	}

	if err := addChain("rp_g0.jws", "rp_g1.jws", "rp_g2.jws",
		protocol.AncestorCredential{CredentialID: cCredID, Presentation: string(cSvcSD)},
		tpCSingle, tpAC, tpABC,
	); err != nil {
		return nil, err
	}
	if err := addChain("bm_g0.jws", "bm_g1.jws", "bm_g2.jws",
		protocol.AncestorCredential{CredentialID: paCredID, Presentation: string(paSD)},
		tpASingle, tpASingle, tpAB,
	); err != nil {
		return nil, err
	}

	return w, nil
}

func decodeGrantPayload(compact string) (protocol.GrantClaims, error) {
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return protocol.GrantClaims{}, fmt.Errorf("invalid compact grant JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return protocol.GrantClaims{}, err
	}
	var claims protocol.GrantClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return protocol.GrantClaims{}, err
	}
	return claims, nil
}
