package runtime

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"grad/platform/gateway"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/platform/state/fabric"
	"grad/platform/workbench"
	"grad/protocol"
	"grad/protocol/registry"
)

func (d *domainWorkbench) secureTransport(dir string) (*tls.Config, map[string]*http.Client, *protocol.DIDWebResolver, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "internal.crt"), filepath.Join(dir, "internal.key"))
	if err != nil {
		return nil, nil, nil, err
	}
	rawCA, err := os.ReadFile(filepath.Join(dir, "internal-ca.crt"))
	if err != nil {
		return nil, nil, nil, err
	}
	roots, err := protocol.ParseTestCAPublic(rawCA)
	if err != nil {
		return nil, nil, nil, err
	}
	if registry.Digest(cert.Certificate[0]) != d.cfg.Peers[d.cfg.DomainID].Fingerprint {
		return nil, nil, nil, fmt.Errorf("local service certificate differs from domain binding")
	}
	server := &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, Certificates: []tls.Certificate{cert},
	}
	routes := make(map[string]string)
	clients := make(map[string]*http.Client)
	for _, domain := range []string{"A", "B", "C"} {
		peer := d.cfg.Peers[domain]
		u, err := url.Parse(peer.URL)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Path != "" ||
			u.RawQuery != "" || u.Fragment != "" || !registry.IsDigest(peer.Fingerprint) {
			return nil, nil, nil, fmt.Errorf("invalid internal service binding for domain %s", domain)
		}
		host, port := u.Hostname(), u.Port()
		if port == "" {
			port = "443"
		}
		routes[strings.ToLower(domain)+".local:443"] = net.JoinHostPort(host, port)
		tr := &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert},
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 || registry.Digest(state.PeerCertificates[0].Raw) != peer.Fingerprint {
					return fmt.Errorf("peer certificate differs from domain binding")
				}
				return nil
			},
		}}
		clients[domain] = &http.Client{
			Transport: tr, Timeout: 55 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("internal service redirects forbidden") },
		}
	}
	resolver, err := protocol.NewMTLSDIDWebResolver(roots, routes, cert)
	if err != nil {
		return nil, nil, nil, err
	}
	root := d.dep.Bootstrap.Root
	raw, err := os.ReadFile(d.inst.RegistryPath(fabric.DIDRelPath(root.DID)))
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = resolver.RegisterPreseed(protocol.RootPreseed{
		DID: root.DID, KeyID: root.KeyID, KeyVersion: root.KeyVersion, PublicKeyHex: root.PublicKey,
		DIDDocumentDigest: root.DocumentDigest, RawDocument: raw,
	})
	return server, clients, resolver, err
}

func (d *domainWorkbench) fromDomain(domain string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := mtls.Caller(r)
		role, did := workbenchTransportRole(domain)
		if !ok || id.Fingerprint != d.cfg.Peers[domain].Fingerprint || id.Role != role || id.DID != did {
			workbench.WriteError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "internal service binding rejected")
			return
		}
		next(w, r)
	}
}

func (d *domainWorkbench) internalHandler() (http.Handler, error) {
	mux := http.NewServeMux()
	docs, err := d.inst.LoadAllDIDDocs()
	if err != nil {
		return nil, err
	}
	localDIDHost := strings.ToLower(d.cfg.DomainID) + ".local"
	for did, doc := range docs {
		u, err := protocol.ParseDIDWebURL(did)
		if err != nil {
			return nil, err
		}
		if u.Host != localDIDHost {
			continue
		}
		mux.HandleFunc("GET "+localDIDHost+u.Path, d.fromDomain("C", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/did+json")
			_, _ = w.Write(doc)
		}))
	}
	switch d.cfg.DomainID {
	case "B":
		mux.HandleFunc("POST "+workbenchDispatchPath, d.fromDomain("A", d.acceptDispatch))
		mux.HandleFunc("GET "+workbenchDispatchPath+"/{runId}", d.fromDomain("A", d.dispatchStatus))
		mux.HandleFunc("POST /internal/workbench/probe", d.fromDomain("A", d.runProbe))
		mux.HandleFunc("POST /v1/internal/order-outcome-receipts", d.fromDomain("C", d.wallet.ReceiptHandler().ServeHTTP))
	case "C":
		mux.HandleFunc("POST /internal/workbench/root", d.fromDomain("A", d.remoteRoot))
		mux.HandleFunc("POST /internal/workbench/root-receipt", d.fromDomain("A", d.remoteRootReceipt))
		mux.HandleFunc("POST /internal/workbench/context", d.fromDomain("B", d.remoteContext))
		mux.HandleFunc("GET /internal/workbench/evidence/{taskId}", d.fromDomain("A", d.remoteEvidence))
		mux.HandleFunc("POST /v1/auth/challenges", d.fromDomain("B", d.gateway.Handler().ServeHTTP))
		mux.HandleFunc("POST /v1/access/execute", d.fromDomain("B", d.gateway.Handler().ServeHTTP))
		mux.HandleFunc("POST /v1/internal/order-outcome-cases", d.fromDomain("B", d.gateway.Handler().ServeHTTP))
		mux.HandleFunc("POST /v1/audit/order-outcomes", d.fromDomain("B", d.reconcileFromB))
	}
	return httpx.WithRequestID(mux), nil
}

func callLocalJSON(ctx context.Context, h http.Handler, method, path string, payload, out any) error {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	r := httptest.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return readWorkbenchResponse(w.Code, w.Body, out)
}

func (d *domainWorkbench) callPeer(ctx context.Context, domain, method, path string, payload, out any) error {
	var raw []byte
	var err error
	if payload != nil {
		raw, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, d.cfg.Peers[domain].URL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.clients[domain].Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return readWorkbenchResponse(resp.StatusCode, resp.Body, out)
}

func readWorkbenchResponse(status int, body io.Reader, out any) error {
	raw, err := io.ReadAll(io.LimitReader(body, 2*1024*1024+1))
	if err != nil {
		return err
	}
	if len(raw) > 2*1024*1024 {
		return fmt.Errorf("workbench response exceeds limit")
	}
	if status < 200 || status >= 300 {
		var response httpx.ErrorEnvelope
		if json.Unmarshal(raw, &response) == nil && response.Code != "" {
			return protocol.NewError(response.Code, "service operation rejected")
		}
		return fmt.Errorf("service operation returned HTTP %d", status)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (d *domainWorkbench) reconcileFromB(w http.ResponseWriter, r *http.Request) {
	var request gateway.AuditOrderOutcomeRequest
	if !readServiceJSON(w, r, &request) {
		return
	}
	if request.Request == nil || request.Request.Actor != d.cfg.Actors["B1"].DID ||
		request.Request.DeploymentID != d.dep.DeploymentID || request.DeploymentID != d.dep.DeploymentID || request.CaseID == "" {
		workbench.WriteError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "original B1 case required")
		return
	}
	var exists bool
	err := d.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM order_outcome_cases
		WHERE deployment_id=$1 AND case_id=$2 AND actor=$3 AND task_id=$4 AND request_hash=$5)`,
		d.dep.DeploymentID, request.CaseID, request.Request.Actor, request.Request.TaskID, request.RequestHash).Scan(&exists)
	if err != nil || !exists {
		workbench.WriteError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "original B1 case required")
		return
	}
	raw, err := json.Marshal(request)
	if err != nil {
		workbench.WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid audit input")
		return
	}
	ctx := mtls.WithIdentity(r.Context(), mtls.Identity{DID: defaultAuditorDID, Role: "C_AUDITOR", MSPID: "CMsp"})
	local := r.Clone(ctx)
	local.Body = io.NopCloser(bytes.NewReader(raw))
	d.gateway.Handler().ServeHTTP(w, local)
}

func readServiceJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	body := http.MaxBytesReader(w, r.Body, 512*1024)
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil || protocol.DecodeStrictJSON(raw, out) != nil {
		workbench.WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid service request")
		return false
	}
	return true
}
