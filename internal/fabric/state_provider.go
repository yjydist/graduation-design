package fabric

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Checkpoint captures the Fabric block height, hash, and revocation epoch anchored in fabric_head.
type Checkpoint struct {
	Height          int64  `json:"blockNumber"`
	Hash            string `json:"blockHash"`
	RevocationEpoch int64  `json:"revocationEpoch"`
}

// ProbeSnapshot captures the adopted original probe identity, block, and monotonic deadline.
type ProbeSnapshot struct {
	TxID           string         `json:"txId"`
	Identity       api.Management `json:"identity"`
	ProbeBlock     uint64         `json:"probeBlockNumber"`
	SentAt         time.Time      `json:"sentAt"`
	Deadline       time.Time      `json:"deadline"`
	AdoptedAt      time.Time      `json:"adoptedAt"`
	SentMonoNs     int64          `json:"sentMonoNs"`
	DeadlineMonoNs int64          `json:"deadlineMonoNs"`
	AdoptedMonoNs  int64          `json:"adoptedMonoNs"`
}

// ConsistentProtocolView holds all protocol records, synced domain certification JWS documents,
// checkpoint metadata, and original probe lease assembled inside a single REPEATABLE READ transaction.
type ConsistentProtocolView struct {
	DeploymentID string
	Checkpoint   Checkpoint
	Probe        ProbeSnapshot
	Bootstrap    api.Bootstrap
	Snapshot     *protocol.SnapshotView
	CertJWSByID  map[string]string
	CertJWSByDom map[string]string
}

// StateProvider assembles consistent protocol snapshots purely from PostgreSQL state views
// without ever falling back to querying Peer latest state.
type StateProvider struct {
	db           *pgxpool.Pool
	deploymentID string
	boot         api.Bootstrap
	bootDigest   string
	runtime      *online

	mu          sync.RWMutex
	staticProbe *ProbeSnapshot
	lastProbe   *ProbeSnapshot
	monoClock   func() time.Time
	afterRoot   func() error
}

// EnsureStateSchema initializes the durable registry and block-view tables before a provider is used.
func EnsureStateSchema(ctx context.Context, db *pgxpool.Pool) error {
	return initSchema(ctx, db, operationsSchema+viewSchema)
}

// NewStateProvider constructs a StateProvider from a verified deployment and optional online probe runtime.
func NewStateProvider(db *pgxpool.Pool, d *deployment, runtime *online) *StateProvider {
	return &StateProvider{
		db:           db,
		deploymentID: d.DeploymentID,
		boot:         d.Bootstrap,
		bootDigest:   d.BootstrapDigest,
		runtime:      runtime,
		monoClock:    time.Now,
	}
}

// NewStateProviderFromBootstrap constructs a StateProvider with explicit deployment ID and Bootstrap anchor.
func NewStateProviderFromBootstrap(db *pgxpool.Pool, deploymentID string, boot api.Bootstrap, runtime *online) *StateProvider {
	raw, _ := json.Marshal(boot)
	return &StateProvider{
		db:           db,
		deploymentID: deploymentID,
		boot:         boot,
		bootDigest:   api.Digest(raw),
		runtime:      runtime,
		monoClock:    time.Now,
	}
}

// SetStaticProbe configures an explicit original probe lease for deterministic testing when online runtime is nil.
func (sp *StateProvider) SetStaticProbe(p *ProbeSnapshot) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if p == nil {
		sp.staticProbe = nil
		return
	}
	cp := *p
	sp.staticProbe = &cp
}

// SetMonoClock overrides the monotonic clock helper used for probe deadline checks (for deterministic tests).
func (sp *StateProvider) SetMonoClock(fn func() time.Time) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if fn == nil {
		sp.monoClock = time.Now
		return
	}
	sp.monoClock = fn
}

// IsProbeFresh validates that an active original probe lease has not reached its monotonic deadline.
func (sp *StateProvider) IsProbeFresh(original ...ProbeSnapshot) (ProbeSnapshot, error) {
	sp.mu.RLock()
	clock := sp.monoClock
	rt := sp.runtime
	staticP := sp.staticProbe
	last := sp.lastProbe
	sp.mu.RUnlock()
	if clock == nil {
		clock = time.Now
	}
	nowMono := clock()
	probe := staticP
	if rt != nil {
		probe = last
	}
	if len(original) > 0 {
		probe = &original[0]
	} else if rt != nil && sp.db != nil && (probe == nil || !nowMono.Before(probe.Deadline)) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		view, err := sp.AssembleProtocolSnapshot(ctx, "", nowMono)
		if err != nil {
			return ProbeSnapshot{}, err
		}
		probe = &view.Probe
	}
	if probe == nil || probe.TxID == "" || !nowMono.Before(probe.Deadline) {
		return ProbeSnapshot{}, protocol.NewError(protocol.ErrCodeStateStale, "no unexpired original probe lease")
	}

	if rt != nil {
		rt.mu.Lock()
		ready, hard := rt.ready, rt.hardError
		rt.mu.Unlock()
		if !ready {
			msg := "online view not ready"
			if hard != nil {
				msg = hard.Error()
			}
			return ProbeSnapshot{}, protocol.NewError(protocol.ErrCodeStateUnavailable, msg)
		}
		rt.mu.Lock()
		sent, exists := rt.attempts[probe.TxID]
		rt.mu.Unlock()
		if !exists || !sent.Equal(probe.SentAt) || !sent.Add(rt.timeLimit).Equal(probe.Deadline) {
			return ProbeSnapshot{}, protocol.NewError(protocol.ErrCodeStateStale, "original probe is not from this runtime")
		}
	}
	if staticP != nil || rt != nil {
		adopted := *probe
		adopted.AdoptedAt = nowMono
		adopted.AdoptedMonoNs = probe.SentMonoNs + nowMono.Sub(probe.SentAt).Nanoseconds()
		return adopted, nil
	}
	return ProbeSnapshot{}, protocol.NewError(protocol.ErrCodeStateStale, "no active original probe lease")
}

// AssembleProtocolSnapshot reads fabric_head and all grant-chain protocol dependencies in one
// PostgreSQL REPEATABLE READ read-only transaction, checking original probe freshness without
// falling back to querying Peer latest state.
func (sp *StateProvider) AssembleProtocolSnapshot(ctx context.Context, leafGrantID string, now time.Time) (*ConsistentProtocolView, error) {
	return sp.assembleAtHeight(ctx, leafGrantID, nil, now)
}

// AssembleHistoricalProtocolSnapshot reconstructs an immutable historical SnapshotView at blockNo
// AssembleHistoricalProtocolSnapshot assembles the protocol snapshot at an exact historical block height
// inside a single REPEATABLE READ transaction after verifying continuous replayed block history up to blockNo.
func (sp *StateProvider) AssembleHistoricalProtocolSnapshot(ctx context.Context, leafGrantID string, blockNo uint64, now time.Time) (*ConsistentProtocolView, error) {
	if blockNo == 0 {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "HISTORY_UNAVAILABLE: blockNo must be >= 1")
	}
	return sp.assembleAtHeight(ctx, leafGrantID, &blockNo, now)
}

func (sp *StateProvider) assembleAtHeight(ctx context.Context, leafGrantID string, historicalBlock *uint64, now time.Time) (*ConsistentProtocolView, error) {
	if sp == nil || sp.db == nil {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "state provider database is nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	tx, err := sp.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "begin repeatable read transaction", err)
	}
	defer tx.Rollback(context.Background())

	var h point
	err = tx.QueryRow(ctx, "SELECT block_no, hash FROM fabric_head WHERE deployment=$1", sp.deploymentID).Scan(&h.Number, &h.Hash)
	if errors.Is(err, pgx.ErrNoRows) || h.Hash == "" {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "fabric_head checkpoint missing")
	}
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "query fabric_head", err)
	}

	sp.mu.RLock()
	rt := sp.runtime
	staticP := sp.staticProbe
	clock := sp.monoClock
	hook := sp.afterRoot
	sp.mu.RUnlock()
	if clock == nil {
		clock = time.Now
	}

	d := &deployment{DeploymentID: sp.deploymentID, Bootstrap: sp.boot, BootstrapDigest: sp.bootDigest}
	v := view{db: sp.db, d: d}

	mode := "online"
	snapPoint := h
	var probeSnap ProbeSnapshot
	if historicalBlock != nil {
		mode = "historical"
		snapPoint.Number = *historicalBlock
		if err := v.historicalPoint(ctx, tx, &snapPoint, h); err != nil {
			return nil, mapViewErr(err)
		}
		hook = nil
	} else if rt != nil {
		lease, epoch, lErr := rt.lease(ctx, tx, h)
		if lErr != nil {
			return nil, mapViewErr(lErr)
		}
		if cErr := rt.checkLease(lease, epoch, clock()); cErr != nil {
			return nil, mapViewErr(cErr)
		}
		probeSnap = ProbeSnapshot{
			TxID:           lease.TxID,
			Identity:       lease.Identity,
			ProbeBlock:     lease.ProbeBlock,
			SentAt:         lease.Sent,
			Deadline:       lease.Deadline,
			AdoptedAt:      lease.Adopted,
			SentMonoNs:     lease.SentMono,
			DeadlineMonoNs: lease.DeadlineMono,
			AdoptedMonoNs:  lease.AdoptedMono,
		}
	} else if staticP != nil {
		if !clock().Before(staticP.Deadline) {
			return nil, protocol.NewError(protocol.ErrCodeStateStale, "original probe monotonic deadline reached")
		}
		probeSnap = *staticP
		probeSnap.AdoptedAt = clock()
	} else {
		return nil, protocol.NewError(protocol.ErrCodeStateStale, "STATE_STALE: no active original probe lease")
	}

	s := &snapshot{
		DeploymentID: sp.deploymentID,
		Mode:         mode,
		point:        snapPoint,
		GrantID:      leafGrantID,
		Records:      map[string]json.RawMessage{},
	}
	r := reader{ctx: ctx, tx: tx, d: d, snapshot: s}

	boot, err := record[api.Bootstrap](r, api.BootstrapKey)
	if err != nil {
		return nil, mapViewErr(err)
	}
	if boot != sp.boot {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "DEPLOYMENT_MISMATCH: view bootstrap")
	}

	// If leafGrantID is specified, assemble full chain dependency closure inside the single REPEATABLE READ tx.
	if leafGrantID != "" {
		if err := r.assemble(leafGrantID, hook); err != nil {
			return nil, mapViewErr(err)
		}
	}

	// Decode assembled records into protocol.SnapshotView
	snapView := &protocol.SnapshotView{
		Height:              snapPoint.Number,
		Now:                 now.UTC(),
		ClockError:          api.ClockError,
		ExactIntervalBounds: true,
		DeploymentID:        sp.deploymentID,
		Root:                boot.Root,
		Domains:             make(map[string]api.Domain),
		Certifications:      make(map[string]api.Certification),
		Identities:          make(map[string]api.Identity),
		Credentials:         make(map[string]api.Credential),
		Tasks:               make(map[string]api.Task),
		Grants:              make(map[string]api.Grant),
		Links:               make(map[string]api.IdentityLink),
	}

	certJWSByID := make(map[string]string)
	certJWSByDom := make(map[string]string)

	for key, raw := range s.Records {
		kind, _, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		switch kind {
		case "domain":
			var rec api.Domain
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Domains[rec.ID] = rec
		case "certification":
			var rec api.Certification
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Certifications[rec.ID] = rec
		case "identity":
			var rec api.Identity
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Identities[rec.ID] = rec
		case "credential":
			var rec api.Credential
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Credentials[rec.ID] = rec
		case "task":
			var rec api.Task
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Tasks[rec.ID] = rec
		case "grant":
			var rec api.Grant
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Grants[rec.ID] = rec
		case "link":
			var rec api.IdentityLink
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Links[rec.ID] = rec
		}
	}

	// Load any identity links at the same REPEATABLE READ snapshot height so dual-domain link state is visible.
	var linkRows pgx.Rows
	if mode == "historical" {
		linkRows, err = tx.Query(ctx, `SELECT DISTINCT ON (key) value FROM fabric_version
			WHERE deployment=$1 AND key LIKE 'link/%' AND block_no <= $2
			ORDER BY key, block_no DESC, tx_index DESC`, sp.deploymentID, snapPoint.Number)
	} else {
		linkRows, err = tx.Query(ctx, "SELECT value FROM fabric_current WHERE deployment=$1 AND key LIKE 'link/%'", sp.deploymentID)
	}
	if err == nil {
		var links []api.IdentityLink
		for linkRows.Next() {
			var raw []byte
			if err := linkRows.Scan(&raw); err == nil && len(raw) > 0 {
				var l api.IdentityLink
				if json.Unmarshal(raw, &l) == nil && l.ID != "" {
					snapView.Links[l.ID] = l
					links = append(links, l)
				}
			}
		}
		linkRows.Close()
		for _, l := range links {
			for _, domID := range []string{l.SourceDomain, l.TargetDomain} {
				if _, exists := snapView.Domains[domID]; !exists && domID != "" {
					if dRaw, dErr := loadOptionalAt(ctx, tx, sp.deploymentID, api.Key("domain", domID), historicalBlock); dErr == nil && len(dRaw) > 0 {
						var dom api.Domain
						if json.Unmarshal(dRaw, &dom) == nil {
							snapView.Domains[dom.ID] = dom
						}
					}
				}
			}
			for _, subID := range []string{l.SourceSubject, l.TargetSubject} {
				if _, exists := snapView.Identities[subID]; !exists && subID != "" {
					if iRaw, iErr := loadOptionalAt(ctx, tx, sp.deploymentID, api.Key("identity", subID), historicalBlock); iErr == nil && len(iRaw) > 0 {
						var id api.Identity
						if json.Unmarshal(iRaw, &id) == nil {
							snapView.Identities[id.ID] = id
						}
					}
				}
			}
		}
	}

	// Optional PA identity (not directly on RP grant path, needed when checking BM/authority presence)
	if paRaw, err := loadOptionalAt(ctx, tx, sp.deploymentID, api.Key("identity", "did:web:a.local:pa"), historicalBlock); err == nil && len(paRaw) > 0 {
		var paID api.Identity
		if json.Unmarshal(paRaw, &paID) == nil {
			snapView.Identities[paID.ID] = paID
		}
	}

	// Ensure every loaded domain also has its active certification record available for delivery/protocol checks.
	for _, dom := range snapView.Domains {
		if dom.Certification == "" {
			continue
		}
		if _, exists := snapView.Certifications[dom.Certification]; !exists {
			if cRaw, cErr := loadOptionalAt(ctx, tx, sp.deploymentID, api.Key("certification", dom.Certification), historicalBlock); cErr == nil && len(cRaw) > 0 {
				var cert api.Certification
				if json.Unmarshal(cRaw, &cert) == nil && cert.ID != "" {
					snapView.Certifications[cert.ID] = cert
				}
			}
		}
	}

	// Load synced certification JWS documents in the same REPEATABLE READ tx
	for domID, dom := range snapView.Domains {
		if dom.Certification == "" {
			continue
		}
		var jws string
		err := tx.QueryRow(ctx, `SELECT cert_jws FROM certification_receipts
			WHERE deployment_id=$1 AND domain_id=$2 AND certification_id=$3 LIMIT 1`,
			sp.deploymentID, domID, dom.Certification).Scan(&jws)
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(ctx, `SELECT cert_jws FROM certification_outbox
				WHERE deployment_id=$1 AND domain_id=$2 AND certification_id=$3 LIMIT 1`,
				sp.deploymentID, domID, dom.Certification).Scan(&jws)
		}
		if err == nil && jws != "" {
			certJWSByID[dom.Certification] = jws
			certJWSByDom[domID] = jws
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if historicalBlock == nil && rt != nil {
		sp.mu.Lock()
		copyProbe := probeSnap
		sp.lastProbe = &copyProbe
		sp.mu.Unlock()
		rt.emit("adopt", &probeEvidence{
			TxID: probeSnap.TxID, Identity: probeSnap.Identity, ProbeBlock: probeSnap.ProbeBlock,
			View: snapPoint, Sent: probeSnap.SentAt, Deadline: probeSnap.Deadline, Adopted: probeSnap.AdoptedAt,
		})
	}

	return &ConsistentProtocolView{
		DeploymentID: sp.deploymentID,
		Checkpoint: Checkpoint{
			Height:          int64(snapPoint.Number),
			Hash:            snapPoint.Hash,
			RevocationEpoch: 0,
		},
		Probe:        probeSnap,
		Bootstrap:    boot,
		Snapshot:     snapView,
		CertJWSByID:  certJWSByID,
		CertJWSByDom: certJWSByDom,
	}, nil
}

func loadOptionalAt(ctx context.Context, tx pgx.Tx, depID, key string, historicalBlock *uint64) ([]byte, error) {
	var raw []byte
	var err error
	if historicalBlock != nil {
		err = tx.QueryRow(ctx, `SELECT value FROM fabric_version WHERE deployment=$1 AND key=$2 AND block_no <= $3
			ORDER BY block_no DESC, tx_index DESC LIMIT 1`, depID, key, *historicalBlock).Scan(&raw)
	} else {
		err = tx.QueryRow(ctx, "SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2", depID, key).Scan(&raw)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

// FindInactiveBlock searches fabric_version for the earliest VALID block >= afterBlock where (kind, id) entered SUSPENDED, REVOKED, or CANCELLED.
func (sp *StateProvider) FindInactiveBlock(ctx context.Context, kind, id string, afterBlock int64) (int64, string, bool, error) {
	if sp == nil || sp.db == nil {
		return 0, "", false, protocol.NewError(protocol.ErrCodeStateUnavailable, "state provider database is nil")
	}
	if afterBlock < 1 {
		afterBlock = 1
	}
	key := api.Key(kind, id)
	rows, err := sp.db.Query(ctx, `SELECT block_no, tx_id, value FROM fabric_version
		WHERE deployment=$1 AND key=$2 AND block_no >= $3
		ORDER BY block_no ASC, tx_index ASC`, sp.deploymentID, key, afterBlock)
	if err != nil {
		return 0, "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var blk int64
		var txID string
		var raw []byte
		if err := rows.Scan(&blk, &txID, &raw); err != nil {
			return 0, "", false, err
		}
		var st struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(raw, &st) == nil && (st.Status == api.Suspended || st.Status == api.Revoked || st.Status == api.Cancelled) {
			return blk, txID, true, nil
		}
	}
	return 0, "", false, rows.Err()
}

func mapViewErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errStale) || strings.Contains(err.Error(), "STATE_STALE") {
		return protocol.NewError(protocol.ErrCodeStateStale, err.Error())
	}
	if errors.Is(err, errUnavailable) || strings.Contains(err.Error(), "MISSING_DEPENDENCY") || strings.Contains(err.Error(), "DEPLOYMENT_MISMATCH") || strings.Contains(err.Error(), "HISTORY_UNAVAILABLE") {
		return protocol.NewError(protocol.ErrCodeStateUnavailable, err.Error())
	}
	if strings.Contains(err.Error(), "INVALID_STATE") {
		return protocol.NewError(protocol.ErrCodeGrantChainInvalid, err.Error())
	}
	return err
}

// GatewayAdapter adapts StateProvider to gateway.StateSource without introducing an import cycle.
func (sp *StateProvider) GatewayAdapter() gateway.StateSource {
	return &gatewayStateAdapter{sp: sp}
}

type gatewayStateAdapter struct {
	sp *StateProvider
}

func (a *gatewayStateAdapter) IsProbeFresh(original ...gateway.ProbeInfo) (gateway.ProbeInfo, error) {
	var probes []ProbeSnapshot
	if len(original) > 0 {
		p := original[0]
		probes = []ProbeSnapshot{{TxID: p.TxID, ProbeBlock: p.ProbeBlock, SentAt: p.SentAt,
			Deadline: p.Deadline, SentMonoNs: p.SentMonoNs, DeadlineMonoNs: p.DeadlineMonoNs}}
	}
	p, err := a.sp.IsProbeFresh(probes...)
	if err != nil {
		return gateway.ProbeInfo{}, err
	}
	return gateway.ProbeInfo{
		TxID:           p.TxID,
		ProbeBlock:     p.ProbeBlock,
		SentAt:         p.SentAt,
		Deadline:       p.Deadline,
		SentMonoNs:     p.SentMonoNs,
		DeadlineMonoNs: p.DeadlineMonoNs,
		CheckedMonoNs:  p.AdoptedMonoNs,
	}, nil
}

func (a *gatewayStateAdapter) AssembleSnapshot(ctx context.Context, leafGrantID string, now time.Time) (*gateway.ConsistentSnapshot, error) {
	view, err := a.sp.AssembleProtocolSnapshot(ctx, leafGrantID, now)
	if err != nil {
		return nil, err
	}
	return toGatewayConsistentSnapshot(view), nil
}

func (a *gatewayStateAdapter) AssembleHistoricalSnapshot(ctx context.Context, leafGrantID string, blockNo int64, now time.Time) (*gateway.ConsistentSnapshot, error) {
	if blockNo <= 0 {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "HISTORY_UNAVAILABLE: blockNo must be >= 1")
	}
	view, err := a.sp.AssembleHistoricalProtocolSnapshot(ctx, leafGrantID, uint64(blockNo), now)
	if err != nil {
		return nil, err
	}
	return toGatewayConsistentSnapshot(view), nil
}

func (a *gatewayStateAdapter) FindInactiveBlock(ctx context.Context, kind, id string, afterBlock int64) (int64, string, bool, error) {
	return a.sp.FindInactiveBlock(ctx, kind, id, afterBlock)
}

func toGatewayConsistentSnapshot(view *ConsistentProtocolView) *gateway.ConsistentSnapshot {
	return &gateway.ConsistentSnapshot{
		DeploymentID:    view.DeploymentID,
		BlockNumber:     view.Checkpoint.Height,
		BlockHash:       view.Checkpoint.Hash,
		RevocationEpoch: view.Checkpoint.RevocationEpoch,
		Probe: gateway.ProbeInfo{
			TxID:           view.Probe.TxID,
			ProbeBlock:     view.Probe.ProbeBlock,
			SentAt:         view.Probe.SentAt,
			Deadline:       view.Probe.Deadline,
			SentMonoNs:     view.Probe.SentMonoNs,
			DeadlineMonoNs: view.Probe.DeadlineMonoNs,
		},
		Snapshot: view.Snapshot,
	}
}
