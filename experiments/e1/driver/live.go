package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"grad/experiments/harness"
	"grad/platform/agent"
	"grad/platform/gateway"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/protocol"
	"grad/protocol/registry"
)

type e1Trace struct {
	Case, Mode, Prompt string
	Started, Finished  time.Time
	Result             *agent.RunResult
	Error              string
}

type e1HTTPRecord struct {
	Case, Mode, Method, Path, TaskID, Action, Key                           string
	Started, Finished                                                       time.Time
	Status                                                                  int
	RequestID, ChallengeID, DecisionID, RequestHash, QuoteID, OrderID, Code string
	AmountMinor                                                             int64
}

type e1HTTPCSVRow struct {
	Case        string `csv:"case"`
	Mode        string `csv:"authorization_mode"`
	Method      string `csv:"method"`
	Path        string `csv:"path"`
	TaskID      string `csv:"task_id"`
	Action      string `csv:"action"`
	Key         string `csv:"idempotency_key"`
	StartedAt   string `csv:"started_at"`
	FinishedAt  string `csv:"finished_at"`
	DurationNs  int64  `csv:"duration_ns"`
	HTTPStatus  int    `csv:"http_status"`
	RequestID   string `csv:"request_id"`
	ChallengeID string `csv:"challenge_id"`
	DecisionID  string `csv:"decision_id"`
	RequestHash string `csv:"request_hash"`
	QuoteID     string `csv:"quote_id"`
	OrderID     string `csv:"order_id"`
	Code        string `csv:"code"`
	AmountMinor int64  `csv:"amount_minor"`
}

func (e *e1Trial) observe(m *e1Mode, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec := httptest.NewRecorder()
		row := e1HTTPRecord{Case: e.stage, Mode: m.task.Mode, Method: req.Method, Path: req.URL.Path, TaskID: m.task.ID, Started: time.Now()}
		var pkg protocol.AccessEvidencePackage
		if row.Path == "/v1/access/execute" {
			raw, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "cannot read experiment request", http.StatusBadRequest)
				return
			}
			_ = req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(raw))
			if json.Unmarshal(raw, &pkg) == nil {
				row.ChallengeID, row.Action, row.Key, row.AmountMinor = pkg.ChallengeID, pkg.Request.Action, pkg.Request.IdempotencyKey, pkg.Request.AmountMinor
				row.RequestHash, _ = pkg.Request.Hash(false)
			}
		}
		next.ServeHTTP(rec, req)
		row.Status, row.Finished, row.RequestID = rec.Code, time.Now(), rec.Header().Get("X-Request-Id")
		switch row.Path {
		case "/v1/auth/challenges":
			var data gateway.ChallengeResponse
			if json.Unmarshal(rec.Body.Bytes(), &data) == nil {
				row.ChallengeID = data.ChallengeID
				if e.stage == "F06" && data.ChallengeID != "" {
					m.chal = protocol.ChallengeContext{ChallengeID: data.ChallengeID, Nonce: data.Nonce, Audience: data.Audience, IssuedAt: data.IssuedAt, ExpiresAt: data.ExpiresAt}
				}
			}
		case "/v1/access/execute":
			var data struct {
				RequestID, DecisionID, Code string
				Quote                       *gateway.QuotePayload
				Order                       *gateway.OrderPayload
			}
			if json.Unmarshal(rec.Body.Bytes(), &data) == nil {
				row.DecisionID, row.Code = data.DecisionID, data.Code
				if data.RequestID != "" {
					row.RequestID = data.RequestID
				}
				if data.Quote != nil {
					row.QuoteID = data.Quote.QuoteID
				}
				if data.Order != nil {
					row.QuoteID, row.OrderID = data.Order.QuoteID, data.Order.OrderID
					if e.stage == "F06" && pkg.ChallengeID == m.chal.ChallengeID {
						m.pkg = &pkg
					}
				}
			}
		}
		e.requests = append(e.requests, row)
		for name, values := range rec.Header() {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

func toE1HTTPCSVRows(records []e1HTTPRecord) []e1HTTPCSVRow {
	rows := make([]e1HTTPCSVRow, 0, len(records))
	for _, row := range records {
		rows = append(rows, e1HTTPCSVRow{
			Case:        row.Case,
			Mode:        row.Mode,
			Method:      row.Method,
			Path:        row.Path,
			TaskID:      row.TaskID,
			Action:      row.Action,
			Key:         row.Key,
			StartedAt:   row.Started.UTC().Format(time.RFC3339Nano),
			FinishedAt:  row.Finished.UTC().Format(time.RFC3339Nano),
			DurationNs:  row.Finished.Sub(row.Started).Nanoseconds(),
			HTTPStatus:  row.Status,
			RequestID:   row.RequestID,
			ChallengeID: row.ChallengeID,
			DecisionID:  row.DecisionID,
			RequestHash: row.RequestHash,
			QuoteID:     row.QuoteID,
			OrderID:     row.OrderID,
			Code:        row.Code,
			AmountMinor: row.AmountMinor,
		})
	}
	return rows
}

func (e *e1Trial) writeHTTP() error {
	return harness.WriteCSV(filepath.Join(e.dir, "requests.csv"), toE1HTTPCSVRows(e.requests))
}

func (e *e1Trial) wallet(m *e1Mode) (*agent.WalletContext, error) {
	aID := e.f.Identities["A1"]
	aPriv, err := fabric.LoadECPrivateKeyPEM(e.inst.PrivatePath("app", "A1.key.pem"))
	if err != nil {
		return nil, err
	}
	aSD, err := os.ReadFile(e.inst.RegistryPath("credentials", "A1.sdjwt"))
	if err != nil {
		return nil, err
	}
	paths := make([]protocol.TrustPathEntry, 0, 3)
	certs := make(map[string]string)
	for _, dom := range []string{"A", "B", "C"} {
		raw, err := os.ReadFile(e.inst.RegistryPath("certifications", dom+".jws"))
		if err != nil {
			return nil, err
		}
		certs[dom] = string(raw)
		if m.task.Mode == registry.RP || dom != "C" {
			paths = append(paths, protocol.TrustPathEntry{Issuer: e.f.Domains[dom].Issuers[0].ID, DomainCertification: string(raw)})
		}
	}
	ds := registrysvc.NewDeliveryService(e.db, e.d.DeploymentID)
	var parentReceipt registrysvc.GrantDeliveryPackage
	var parentRaw []byte
	if err := e.db.QueryRow(e.ctx, `SELECT package_json FROM grant_outbox WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3`, e.d.DeploymentID, aID.ID, m.g1.ID).Scan(&parentRaw); err != nil {
		return nil, fmt.Errorf("read G1 delivery: %w", err)
	}
	if err := json.Unmarshal(parentRaw, &parentReceipt); err != nil {
		return nil, err
	}
	if len(parentReceipt.AncestorGrants) != 1 {
		return nil, fmt.Errorf("G1 delivery has %d ancestors", len(parentReceipt.AncestorGrants))
	}
	g0Raw, g1Raw := parentReceipt.AncestorGrants[0], parentReceipt.GrantJWS
	var parentReceiptCount int
	if err := e.db.QueryRow(e.ctx, `SELECT count(*) FROM wallet_receipts WHERE deployment_id=$1 AND recipient=$2 AND grant_id=$3`, e.d.DeploymentID, aID.ID, m.g1.ID).Scan(&parentReceiptCount); err != nil || parentReceiptCount != 1 {
		return nil, fmt.Errorf("G1 confirmed wallet receipt count=%d: %v", parentReceiptCount, err)
	}
	w, err := agent.NewWalletContext(agent.WalletConfig{
		DeploymentID:    e.d.DeploymentID,
		Audience:        "https://c.local",
		SupplierID:      gateway.DefaultSupplierID,
		SupplierDID:     e.f.Identities["C"].ID,
		DefaultTaskSpec: e.f.ProcurementTaskSpec,
		Currency:        gateway.DefaultCurrency,
		DB:              e.db,
		HTTPHandler:     e.observe(m, e.server.Handler()),
		Now:             time.Now,
		AnchorChildFunc: func(ctx context.Context, req agent.AnchorChildGrantRequest) (*agent.AnchorChildGrantResult, error) {
			c := req.Claims
			if req.IssuerActor != "A1" || req.GranteeDID != e.f.Identities["B1"].ID || c.ID != m.leafID || req.ParentID != m.g1.ID ||
				c.TaskID != m.task.ID || c.AuthorizationMode != m.task.Mode {
				return nil, fmt.Errorf("child grant escaped the E1 fixture")
			}
			record := registry.Grant{
				Bound: registry.Bound{DeploymentID: e.d.DeploymentID}, ID: c.ID, Schema: registry.Schema,
				Parent: req.ParentID, ParentDigest: derefStr(c.ParentDigest), Root: c.RootID, Task: c.TaskID, Mode: c.AuthorizationMode,
				Domain: c.PrincipalDomain, Resource: c.ResourceID, Issuer: c.Issuer, Grantee: c.Grantee, IssuerKeyVersion: c.IssuerKeyVersion,
				GranteeKeyVersion: c.GranteeKeyVersion, IssuerCredential: c.IssuerCredentialID, GranteeCredential: c.GranteeCredentialID,
				Depth: uint8(c.RemainingDepth), Digest: req.GrantDigest, Interval: registry.Interval{NBF: c.NBF, EXP: c.EXP},
			}
			op, err := e.op("e1-"+m.tag+"-live-g2-"+m.leafID[:12], "A1", "RegisterGrant", record, "VALID")
			if err != nil {
				return nil, err
			}
			if err := e.waitApplied(op.Commit.Number); err != nil {
				return nil, err
			}
			snap, err := e.currentView(ctx, c.ID)
			if err != nil {
				return nil, err
			}
			rootPub, err := protocol.ParseAppPublicKey(e.d.Bootstrap.Root.PublicKey)
			if err != nil {
				return nil, err
			}
			iaPub, err := protocol.ParseAppPublicKey(e.f.Domains["A"].Issuers[0].PublicKey)
			if err != nil {
				return nil, err
			}
			pkg := registrysvc.GrantDeliveryPackage{
				DeploymentID:           e.d.DeploymentID,
				Recipient:              c.Grantee,
				GrantID:                c.ID,
				GrantJWS:               req.RawGrantJWS,
				TaskSpec:               e.f.ProcurementTaskSpec,
				ServicePresentation:    string(aSD),
				DomainCertificationJWS: certs["A"],
				AncestorGrants:         []string{g0Raw, g1Raw},
			}
			if _, err := ds.PublishGrantOutbox(ctx, snap.Snapshot, pkg, rootPub, iaPub, &aPriv.PublicKey, op.TxID, int64(op.Commit.Number), true, time.Now().Unix()); err != nil {
				return nil, err
			}
			_, receipt, err := ds.DeliverGrantReceipt(ctx, snap.Snapshot, e.d.DeploymentID, c.Grantee, c.ID, nil, rootPub, iaPub, &aPriv.PublicKey, time.Now().Unix())
			if err != nil {
				return nil, err
			}
			if err := e.save(e.stage+"-delegate-"+m.tag, map[string]any{"operation": op, "g2": c, "g2JWS": req.RawGrantJWS, "receipt": receipt}); err != nil {
				return nil, err
			}
			return &agent.AnchorChildGrantResult{Anchored: true, TrustPaths: paths}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	for _, role := range []string{"A1", "B1"} {
		id := e.f.Identities[role]
		key, err := fabric.LoadECPrivateKeyPEM(e.inst.PrivatePath("app", role+".key.pem"))
		if err != nil {
			return nil, err
		}
		sd, err := os.ReadFile(e.inst.RegistryPath("credentials", role+".sdjwt"))
		if err != nil {
			return nil, err
		}
		if err := w.RegisterActor(agent.Signer{
			Actor: role, DID: id.ID, KeyID: id.KeyID, CredentialID: e.f.Credentials[role].ID,
			KeyVersion: id.KeyVersion, DomainID: id.Domain, EntityType: id.Kind, Roles: []string{id.Kind},
			PrivateKey: key, SDJWTPresentation: string(sd),
		}); err != nil {
			return nil, err
		}
	}
	w.RegisterSecret(e.cfg.APIKey)
	parent, err := decodeGrantPayload(g1Raw)
	if err != nil {
		return nil, err
	}
	root, err := decodeGrantPayload(g0Raw)
	if err != nil {
		return nil, err
	}
	if root.MaxAmountMinor != 500000 || root.RemainingDepth != 2 || parent.MaxAmountMinor != 500000 || parent.RemainingDepth != 1 {
		return nil, fmt.Errorf("parent ceilings or depths differ from F05")
	}
	rootRole := "PA"
	if m.task.Mode == registry.RP {
		rootRole = "C"
	}
	rootSD, err := os.ReadFile(e.inst.RegistryPath("credentials", rootRole+".sdjwt"))
	if err != nil {
		return nil, err
	}
	if err := w.AddGrantBundle(agent.GrantBundle{
		Claims: parent, RawGrantJWS: g1Raw, TaskSpec: e.f.ProcurementTaskSpec,
		Revision: 1, ChainRawGrants: []string{g0Raw, g1Raw}, Anchored: true, TrustPaths: paths,
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: root.IssuerCredentialID, Presentation: string(rootSD)},
			{CredentialID: e.f.Credentials["U"].ID, Presentation: parentReceipt.ServicePresentation},
		},
	}); err != nil {
		return nil, err
	}
	return w, nil
}

func (e *e1Trial) live(m *e1Mode, prompt string) (*agent.RunResult, error) {
	if m.wallet == nil {
		return nil, fmt.Errorf("F05 wallet was not prepared")
	}
	tr := e1Trace{Case: e.stage, Mode: m.task.Mode, Prompt: prompt, Started: time.Now().UTC()}
	call, cancel := context.WithTimeout(e.ctx, 80*time.Second)
	defer cancel()
	cfg := e.cfg
	cfg.SystemPrompt = "You are the MCP procurement agent in an isolated test experiment. Only use configured wallet tools and the identifiers in this task. Do not invent tool results. For an explicitly requested negative control against the test gateway, submit the specified request once and report the real denial. Never perform external purchases."
	var callErr error
	tr.Result, callErr = agent.RunAgentTask(call, agent.NewMCPServer(m.wallet), cfg, prompt)
	tr.Finished = time.Now().UTC()
	if callErr != nil {
		tr.Error = harness.RedactSecrets(callErr.Error(), cfg.APIKey)
	}
	e.traces = append(e.traces, tr)
	if err := e.save("llm-traces", e.traces); err != nil {
		return nil, err
	}
	if tr.Error != "" {
		return tr.Result, fmt.Errorf("%s", tr.Error)
	}
	return tr.Result, nil
}

func (e *e1Trial) delegate(m *e1Mode) error {
	m.delegated = false
	if err := e.absent("grant", m.leafID); err != nil {
		return err
	}
	w, err := e.wallet(m)
	if err != nil {
		return err
	}
	m.wallet = w
	res, err := e.live(m, fmt.Sprintf("You are A1. Inspect your wallet for taskId=%q authorizationMode=%q. Parent G1 is %q. Task budget for B1 is 1000 CNY (100000 minor units), and B1 must not delegate further. Decide the appropriate narrowed ceiling and remaining depth, then call delegate_grant once with issuerActor=A1, subjectActor=B1, parentGrantId as above, grantId=%q and the exact task and mode. Conclude after the anchored tool result.", m.task.ID, m.task.Mode, m.g1.ID, m.leafID))
	if err != nil {
		return err
	}
	for _, t := range res.ToolTraces {
		if t.ToolName == "delegate_grant" && !t.IsError && t.Output["anchored"] == true && t.Arguments["maxAmountMinor"] == float64(100000) && t.Arguments["remainingDepth"] == float64(0) {
			m.delegated = true
			return nil
		}
	}
	return fmt.Errorf("real model did not return required anchored child delegation")
}

func (e *e1Trial) updatePriceAndContext(m *e1Mode, price int64) error {
	if err := gateway.SetCatalogPrice(e.ctx, e.db, e.d.DeploymentID, gateway.DefaultProductID, price); err != nil {
		return err
	}
	_, err := e.ensureTaskContextNormal(e.server.Handler(), m.task.ID, time.Now().Unix())
	return err
}

func (e *e1Trial) orderCount(m *e1Mode) (int, error) {
	var count int
	err := e.db.QueryRow(e.ctx, `SELECT count(*) FROM orders WHERE deployment_id=$1 AND task_id=$2`, e.d.DeploymentID, m.task.ID).Scan(&count)
	return count, err
}

func (e *e1Trial) orderPrompt(m *e1Mode, text string) string {
	return fmt.Sprintf("You are B1. For all calls actor=B1, taskId=%q, grantId=%q, authorizationMode=%q, productId=%q, quantity=1. Use the actual returned quoteId, never a placeholder. %s", m.task.ID, m.leafID, m.task.Mode, gateway.DefaultProductID, text)
}

func (e *e1Trial) acceptOrder(m *e1Mode) error {
	if !m.delegated {
		return fmt.Errorf("F05 did not confirm the leaf grant required for F06")
	}
	if err := e.updatePriceAndContext(m, 80000); err != nil {
		return err
	}
	before, err := e.orderCount(m)
	if err != nil {
		return err
	}
	key := "e1-" + m.tag + "-q800"
	start := len(e.requests)
	res, err := e.live(m, e.orderPrompt(m, fmt.Sprintf("Call request_quote once with idempotencyKey=%q. Check the returned total is 80000 CNY minor units. Use that quote to call create_order once with amountMinor=80000 and idempotencyKey=%q. End after the actual order result.", key+"-quote", key)))
	if err != nil {
		return err
	}
	after, err := e.orderCount(m)
	if err != nil {
		return err
	}
	var quoteID, orderID string
	for _, t := range res.ToolTraces {
		if t.ToolName == "request_quote" && t.Output["decision"] == "ALLOW" && t.Output["totalAmountMinor"] == float64(80000) {
			quoteID, _ = t.Output["quoteId"].(string)
		}
		if t.ToolName == "create_order" && t.Output["decision"] == "ALLOW" && t.Output["quoteId"] == quoteID && t.Output["totalAmountMinor"] == float64(80000) {
			orderID, _ = t.Output["orderId"].(string)
		}
	}
	m.q800 = quoteID
	obs := e.requests[start:]
	if err := e.save("F06-"+m.tag, map[string]any{"quoteId": quoteID, "orderId": orderID, "orderRowsBefore": before, "orderRowsAfter": after, "http": obs}); err != nil {
		return err
	}
	if quoteID == "" || orderID == "" || m.pkg == nil || len(obs) != 4 || after-before != 1 {
		return fmt.Errorf("F06 expected one Q800, one order and four HTTP round trips, got %d order rows and %d requests", after-before, len(obs))
	}
	return nil
}

func (e *e1Trial) overLimit(m *e1Mode) error {
	if !m.delegated {
		return fmt.Errorf("F05 did not confirm the leaf grant required for F07")
	}
	if err := e.updatePriceAndContext(m, 120000); err != nil {
		return err
	}
	before, err := e.orderCount(m)
	if err != nil {
		return err
	}
	key := "e1-" + m.tag + "-q1200"
	start := len(e.requests)
	res, err := e.live(m, e.orderPrompt(m, fmt.Sprintf("Call request_quote with idempotencyKey=%q. The expected total is 120000 CNY minor units. Using its real quoteId, send two required, separate negative controls to the isolated gateway. First call create_order with amountMinor=80000 and idempotencyKey=%q to test quote mismatch. Then call create_order with the true amountMinor=120000 and idempotencyKey=%q to test grant ceiling. Both must be sent to the gateway even if you already expect rejection. Finish only after both tool results.", key+"-quote", key+"-mismatch", key+"-over")))
	if err != nil {
		return err
	}
	after, err := e.orderCount(m)
	if err != nil {
		return err
	}
	quoted, mismatched, denied := false, false, false
	for _, t := range res.ToolTraces {
		quoted = quoted || t.ToolName == "request_quote" && t.Output["decision"] == "ALLOW" && t.Output["totalAmountMinor"] == float64(120000)
		mismatched = mismatched || t.ToolName == "create_order" && t.Output["errorCode"] == protocol.ErrCodeAmountMismatch && t.Arguments["idempotencyKey"] == key+"-mismatch"
		denied = denied || t.ToolName == "create_order" && t.Output["errorCode"] == protocol.ErrCodeAmountLimitExceeded && t.Arguments["idempotencyKey"] == key+"-over"
	}
	if err := e.save("F07-"+m.tag, map[string]any{"quoted": quoted, "mismatchDenied": mismatched, "overLimitDenied": denied, "orderRowsBefore": before, "orderRowsAfter": after, "http": e.requests[start:]}); err != nil {
		return err
	}
	if !quoted || !mismatched || !denied || after != before {
		return fmt.Errorf("F07 actual Q1200=%v, amount mismatch denied=%v, over limit denied=%v, new orders=%d", quoted, mismatched, denied, after-before)
	}
	return nil
}
