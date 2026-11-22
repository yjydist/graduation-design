package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/experiments/harness"
	"grad/platform/agent"
	"grad/platform/gateway"
	"grad/platform/policy"
	"grad/platform/registrysvc"
	platformrt "grad/platform/runtime"
	"grad/platform/state"
	"grad/platform/state/fabric"
	"grad/protocol"
	"grad/protocol/registry"
)

const (
	clockTimebaseHostUTC = "host-utc-unix-ns"
	defaultSupplierID    = gateway.DefaultSupplierID
	defaultAudience      = "https://c.local"
)

type e6Config struct {
	revision       string
	dir            string
	out            string
	mode           string
	configuration  string
	probeInterval  time.Duration
	probeLifetime  time.Duration
	detectInterval time.Duration
	revokeAfter    time.Duration
	duration       time.Duration
	instances      int
	seed           int
}

func validateE6Config(cfg e6Config) (modeShort, authMode, configName string, err error) {
	if strings.TrimSpace(cfg.dir) == "" || strings.TrimSpace(cfg.out) == "" {
		return "", "", "", fmt.Errorf("dir and out are required")
	}
	modeShort = strings.ToUpper(strings.TrimSpace(cfg.mode))
	switch modeShort {
	case "RP":
		authMode = registry.RP
	case "BM":
		authMode = registry.BM
	default:
		return "", "", "", fmt.Errorf("mode must be RP or BM, got %q", cfg.mode)
	}
	configName = strings.ToUpper(strings.TrimSpace(cfg.configuration))
	if configName != "B0" && configName != "B1" {
		return "", "", "", fmt.Errorf("configuration must be B0 or B1, got %q", cfg.configuration)
	}
	if cfg.instances < 1 || cfg.instances > 2 {
		return "", "", "", fmt.Errorf("instances must be 1 or 2 (dedicated probe1/probe2 roles), got %d", cfg.instances)
	}
	if cfg.probeInterval <= 0 {
		return "", "", "", fmt.Errorf("probe-interval must be positive, got %s", cfg.probeInterval)
	}
	if cfg.probeLifetime < cfg.probeInterval {
		return "", "", "", fmt.Errorf("probe-lifetime (%s) must be >= probe-interval (%s)", cfg.probeLifetime, cfg.probeInterval)
	}
	if cfg.detectInterval <= 0 {
		return "", "", "", fmt.Errorf("detect-interval must be positive, got %s", cfg.detectInterval)
	}
	if cfg.revokeAfter < 0 {
		return "", "", "", fmt.Errorf("revoke-after must be non-negative, got %s", cfg.revokeAfter)
	}
	if cfg.duration <= 0 {
		return "", "", "", fmt.Errorf("duration must be positive, got %s", cfg.duration)
	}
	return modeShort, authMode, configName, nil
}

type probeSlotRecord struct {
	Phase              string
	InstanceID         string
	ProbeRole          string
	Seq                int64
	PlannedAtNs        int64
	ActualIntervalNs   *int64
	SubmittedAtNs      *int64
	DecisionAtNs       *int64
	CommittedAtNs      *int64
	RespondedAtNs      *int64
	DecisionAtSec      *int64
	IdempotencyKey     string
	RequestID          string
	ChallengeID        string
	DecisionID         string
	OrderID            string
	HTTPStatus         *int
	Code               string
	Outcome            string
	Disposition        string // allowed, denied, error, missed, timeout
	BlockNumber        *int64
	BlockHash          string
	G1StatusAtBlock    string
	ProbeTxID          string
	ProbeBlock         *int64
	ProbeSentAtNs      *int64
	ProbeDeadlineNs    *int64
	ProbeSentMonoNs    *int64
	ProbeCheckedMonoNs *int64
	ProbeDeadlineMono  *int64
	UnobservedReason   string
}

type revocationCSVRow struct {
	RunID               string `csv:"run_id"`
	Mode                string `csv:"mode"`
	Configuration       string `csv:"configuration"`
	RevokedGrantID      string `csv:"revoked_grant_id"`
	RevocationTxID      string `csv:"revocation_tx_id"`
	RevocationBlockR    uint64 `csv:"revocation_block_r"`
	RevocationBlockHash string `csv:"revocation_block_hash"`
	TxIndex             int    `csv:"tx_index"`
	ValidationCode      string `csv:"validation_code"`
	TSubmitNs           int64  `csv:"t_submit_ns"`
	TValidNs            int64  `csv:"t_valid_ns"`
	TApplyNs            string `csv:"t_apply_ns"`
	InstanceID          string `csv:"instance_id"`
	ProbeRole           string `csv:"probe_role"`
	TAdoptNs            string `csv:"t_adopt_ns"`
	AdoptBlockH         string `csv:"adopt_block_h"`
	ProbeIntervalMs     int64  `csv:"probe_interval_ms"`
	ProbeLifetimeMs     int64  `csv:"probe_lifetime_ms"`
	DetectIntervalMs    int64  `csv:"detect_interval_ms"`
	ClockTimebase       string `csv:"clock_timebase"`
	ClockResolutionNs   int64  `csv:"clock_resolution_ns"`
	ClockErrorNs        int64  `csv:"clock_error_ns"`
	Status              string `csv:"status"`
	UnobservedReason    string `csv:"unobserved_reason"`
}

type requestCSVRow struct {
	RunID              string `csv:"run_id"`
	Mode               string `csv:"mode"`
	Configuration      string `csv:"configuration"`
	Phase              string `csv:"phase"`
	InstanceID         string `csv:"instance_id"`
	ProbeRole          string `csv:"probe_role"`
	Seq                int64  `csv:"seq"`
	PlannedAtNs        int64  `csv:"planned_at_ns"`
	ActualIntervalNs   string `csv:"actual_interval_ns"`
	SubmittedAtNs      string `csv:"submitted_at_ns"`
	DecisionAtNs       string `csv:"decision_at_ns"`
	CommittedAtNs      string `csv:"committed_at_ns"`
	RespondedAtNs      string `csv:"responded_at_ns"`
	DecisionAtSec      string `csv:"decision_at_sec"`
	IdempotencyKey     string `csv:"idempotency_key"`
	RequestID          string `csv:"request_id"`
	ChallengeID        string `csv:"challenge_id"`
	DecisionID         string `csv:"decision_id"`
	OrderID            string `csv:"order_id"`
	HTTPStatus         string `csv:"http_status"`
	Code               string `csv:"code"`
	Outcome            string `csv:"outcome"`
	Disposition        string `csv:"disposition"`
	BlockNumber        string `csv:"block_number"`
	BlockHash          string `csv:"block_hash"`
	G1StatusAtBlock    string `csv:"g1_status_at_block"`
	ProbeTxID          string `csv:"probe_tx_id"`
	ProbeBlock         string `csv:"probe_block"`
	ProbeSentAtNs      string `csv:"probe_sent_at_ns"`
	ProbeDeadlineNs    string `csv:"probe_deadline_ns"`
	ProbeSentMonoNs    string `csv:"probe_sent_mono_ns"`
	ProbeCheckedMonoNs string `csv:"probe_checked_mono_ns"`
	ProbeDeadlineMono  string `csv:"probe_deadline_mono_ns"`
	ClockTimebase      string `csv:"clock_timebase"`
	ClockResolutionNs  int64  `csv:"clock_resolution_ns"`
	UnobservedReason   string `csv:"unobserved_reason"`
}

type ctxKeySnapshotCapture struct{}

type snapshotCapture struct {
	mu   sync.Mutex
	snap *state.StateSnapshot
}

func (c *snapshotCapture) set(s *state.StateSnapshot) {
	c.mu.Lock()
	c.snap = s
	c.mu.Unlock()
}

func (c *snapshotCapture) get() *state.StateSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snap
}

type observingStateSource struct {
	state.StateSource
}

func (o *observingStateSource) AssembleSnapshot(ctx context.Context, leafGrantID string, now time.Time) (*state.StateSnapshot, error) {
	snap, err := o.StateSource.AssembleSnapshot(ctx, leafGrantID, now)
	if err == nil && snap != nil {
		if capObj, ok := ctx.Value(ctxKeySnapshotCapture{}).(*snapshotCapture); ok && capObj != nil {
			capObj.set(snap)
		}
	}
	return snap, err
}

type instanceTracker struct {
	id        string
	probeRole string
	provider  *fabric.StateProvider
	stop      func()
	server    *gateway.Server

	mu            sync.Mutex
	timings       map[string]gateway.DecisionTiming
	firstAdoptRAt *time.Time
	firstAdoptRH  *int64
	adopts        []fabric.AdoptEvent
}

func (t *instanceTracker) recordTiming(dt gateway.DecisionTiming) {
	t.mu.Lock()
	t.timings[dt.DecisionID] = dt
	t.mu.Unlock()
}

func (t *instanceTracker) lookupTiming(decisionID string) (gateway.DecisionTiming, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	dt, ok := t.timings[decisionID]
	return dt, ok
}

func (t *instanceTracker) recordAdopt(ev fabric.AdoptEvent, revBlock int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.adopts = append(t.adopts, ev)
	if revBlock > 0 && int64(ev.BlockNumber) >= revBlock && t.firstAdoptRAt == nil {
		at := ev.AdoptedAt.UTC()
		h := int64(ev.BlockNumber)
		t.firstAdoptRAt = &at
		t.firstAdoptRH = &h
	}
}

func (t *instanceTracker) resolveFirstAdopt(revBlock int64) (*time.Time, *int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.firstAdoptRAt != nil {
		return t.firstAdoptRAt, t.firstAdoptRH
	}
	for _, ev := range t.adopts {
		if int64(ev.BlockNumber) >= revBlock {
			at := ev.AdoptedAt.UTC()
			h := int64(ev.BlockNumber)
			t.firstAdoptRAt = &at
			t.firstAdoptRH = &h
			return t.firstAdoptRAt, t.firstAdoptRH
		}
	}
	return nil, nil
}

type probeMaterial struct {
	actorDID       string
	actorKeyID     string
	actorPriv      *ecdsa.PrivateKey
	leafPresPrefix string
	taskID         string
	taskSpec       protocol.TaskSpec
	authMode       string
	quoteID        string
	ancestors      []protocol.AncestorCredential
	grants         []string
	trustPaths     []protocol.TrustPathEntry
	deploymentID   string
}

func registerE6Flags(fs *flag.FlagSet, cfg *e6Config) {
	fs.StringVar(&cfg.revision, "revision", "", "source commit")
	fs.StringVar(&cfg.dir, "dir", "", "isolated Fabric instance directory")
	fs.StringVar(&cfg.out, "out", "", "run output directory")
	fs.StringVar(&cfg.mode, "mode", "RP", "authorization mode (RP or BM)")
	fs.StringVar(&cfg.configuration, "configuration", "B0", "verification configuration (B0 or B1)")
	fs.DurationVar(&cfg.probeInterval, "probe-interval", registry.ProbeInterval, "state probe send interval")
	fs.DurationVar(&cfg.probeLifetime, "probe-lifetime", registry.ProbeLifetime, "state probe lifetime (deltaState)")
	fs.DurationVar(&cfg.detectInterval, "detect-interval", 20*time.Millisecond, "planned order probe interval")
	fs.DurationVar(&cfg.revokeAfter, "revoke-after", time.Second, "pre-revocation probing baseline")
	fs.DurationVar(&cfg.duration, "duration", 12*time.Second, "post-revocation probing duration")
	fs.IntVar(&cfg.instances, "instances", 2, "number of gateway instances sharing C view (1 or 2)")
	fs.IntVar(&cfg.seed, "seed", 1109, "seed identifier")
}

func main() {
	var cfg e6Config
	registerE6Flags(flag.CommandLine, &cfg)
	flag.Parse()

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runE6(sigCtx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runE6(ctx context.Context, cfg e6Config) (retErr error) {
	modeShort, authMode, configName, err := validateE6Config(cfg)
	if err != nil {
		return err
	}
	cfg.configuration = configName

	runID := filepath.Base(cfg.out)
	startedAt := time.Now().UTC()
	clockResNs := harness.MeasureClockResolutionNs(2000)

	eventPath := filepath.Join(cfg.out, "events.jsonl")
	eventFile, err := os.Create(eventPath)
	if err != nil {
		return err
	}
	var eventMu sync.Mutex
	emitEvent := func(kind string, at time.Time, details any) {
		eventMu.Lock()
		defer eventMu.Unlock()
		_ = json.NewEncoder(eventFile).Encode(map[string]any{
			"at":      at.UTC().Format(time.RFC3339Nano),
			"atNs":    at.UTC().UnixNano(),
			"event":   kind,
			"details": details,
		})
	}
	defer func() {
		eventMu.Lock()
		_ = eventFile.Close()
		eventMu.Unlock()
	}()

	inst, err := fabric.OpenInstance(cfg.dir)
	if err != nil {
		return fmt.Errorf("open Fabric instance: %w", err)
	}
	d, err := inst.Deploy(ctx, false)
	if err != nil {
		return fmt.Errorf("deploy registry chaincode: %w", err)
	}
	db, err := inst.Database(ctx)
	if err != nil {
		return fmt.Errorf("connect view database: %w", err)
	}
	defer db.Close()

	setup := e6ProcurementSetup(d.DeploymentID, runID, cfg.seed)
	seedReport, err := platformrt.SeedProcurement(ctx, inst, db, d, setup)
	if err != nil {
		return fmt.Errorf("seed procurement fixtures: %w", err)
	}
	fx := seedReport.Fixtures()
	if err := inst.ApplyCommittedRegistry(ctx, db, d); err != nil {
		return fmt.Errorf("apply committed registry: %w", err)
	}
	if err := gateway.EnsureSchema(ctx, db, d.DeploymentID, defaultSupplierID); err != nil {
		return fmt.Errorf("ensure gateway schema: %w", err)
	}
	if err := platformrt.SyncSeedDeliveries(ctx, inst, db, d, seedReport); err != nil {
		return fmt.Errorf("sync seed deliveries: %w", err)
	}
	didServer, resolver, err := inst.StartRegistryDIDResolver(d)
	if err != nil {
		return fmt.Errorf("start registry DID resolver: %w", err)
	}
	defer didServer.Close()

	var task registry.Task
	var g0, g1, g2 registry.Grant
	if authMode == registry.RP {
		task, g0, g1, g2 = fx.RPTask, fx.RPG0, fx.RPG1, fx.RPG2
	} else {
		task, g0, g1, g2 = fx.BMTask, fx.BMG0, fx.BMG1, fx.BMG2
	}

	// Verify G1 and G2 are active and well before deadlines.
	nowSec := time.Now().UTC().Unix()
	minExp := min(task.EXP, min(g0.EXP, min(g1.EXP, min(g2.EXP, fx.Certifications["B"].Certification.EXP))))
	if nowSec+120 >= minExp {
		return fmt.Errorf("fixtures expire too soon: now=%d minExp=%d", nowSec, minExp)
	}

	policyDeadline := minExp
	bundleFiles, bundleDigest, err := policy.BuildDefaultBundle(d.DeploymentID, fx.Identities["C"].ID, policy.DefaultPolicyVersion, d.Bootstrap.Root, &policyDeadline)
	if err != nil {
		return fmt.Errorf("build policy bundle: %w", err)
	}
	bundle, err := policy.VerifyAndLoadBundle(bundleFiles, d.DeploymentID, fx.Identities["C"].ID, d.Bootstrap.Root, bundleDigest)
	if err != nil {
		return fmt.Errorf("verify policy bundle: %w", err)
	}

	// Merge deployment, effective probe settings, clock metadata, fixture/policy digests, and revocation targets into manifest.json.
	var fixtureDigest any
	if sum, readErr := harness.SHA256File(inst.RegistryPath("fixtures.json")); readErr == nil {
		fixtureDigest = sum
	}
	if err := harness.MergeJSON(filepath.Join(cfg.out, "manifest.json"), map[string]any{
		"stateSource": state.SourceFabric,
		"deployment": map[string]any{
			"deploymentId":          d.DeploymentID,
			"channelId":             d.ChannelID,
			"genesisHash":           d.GenesisHash,
			"instanceId":            d.InstanceID,
			"registryName":          d.RegistryName,
			"chaincodeSourceSha256": d.SourceDigest,
			"chaincodeBuildSha256":  d.BuildDigest,
		},
		"policyDigest":      bundle.PolicyDigest,
		"fixtureDigest":     fixtureDigest,
		"clockTimebase":     clockTimebaseHostUTC,
		"clockResolutionNs": clockResNs,
		"clockErrorNs":      int64(0),
		"effectiveSampling": map[string]any{
			"modeShort":         modeShort,
			"authorizationMode": authMode,
			"configuration":     cfg.configuration,
			"taskId":            task.ID,
			"rootGrantId":       g0.ID,
			"revokedGrantId":    g1.ID,
			"leafGrantId":       g2.ID,
			"gatewayInstances":  cfg.instances,
			"probeIntervalMs":   cfg.probeInterval.Milliseconds(),
			"probeLifetimeMs":   cfg.probeLifetime.Milliseconds(),
			"detectIntervalMs":  cfg.detectInterval.Milliseconds(),
			"revokeAfterMs":     cfg.revokeAfter.Milliseconds(),
			"postRevokeDurMs":   cfg.duration.Milliseconds(),
		},
	}); err != nil {
		return err
	}

	// Shared block_applied map across instances (first time C's shared view applies each block).
	var applyMu sync.Mutex
	blockAppliedAt := map[uint64]time.Time{}
	var revBlockAtomic atomic.Int64

	probeRoles := []string{"probe1", "probe2"}[:cfg.instances]
	trackers := make([]*instanceTracker, 0, cfg.instances)
	defer func() {
		for _, tr := range trackers {
			if tr.stop != nil {
				tr.stop()
			}
		}
	}()

	for idx, role := range probeRoles {
		instID := fmt.Sprintf("gw-%d", idx+1)
		tr := &instanceTracker{
			id:        instID,
			probeRole: role,
			timings:   map[string]gateway.DecisionTiming{},
		}
		provider, stopFn, err := inst.StartObservedStateProvider(ctx, db, d, role, g2.ID, cfg.probeInterval, cfg.probeLifetime, func(ev string, at time.Time, details any) {
			emitEvent(ev, at, map[string]any{"instanceId": instID, "probeRole": role, "data": details})
			switch v := details.(type) {
			case fabric.BlockAppliedEvent:
				applyMu.Lock()
				if _, exists := blockAppliedAt[v.BlockNumber]; !exists {
					blockAppliedAt[v.BlockNumber] = v.AppliedAt
				}
				applyMu.Unlock()
			case fabric.AdoptEvent:
				tr.recordAdopt(v, revBlockAtomic.Load())
			}
		})
		if err != nil {
			return fmt.Errorf("start continuous StateProvider for %s (%s): %w", instID, role, err)
		}
		tr.provider = provider
		tr.stop = stopFn

		var sigCache *protocol.SignatureCache
		if strings.EqualFold(cfg.configuration, "B1") {
			sigCache = protocol.NewSignatureCache()
		}
		srv, err := gateway.NewServer(gateway.ServerConfig{
			DB:                  db,
			State:               &observingStateSource{StateSource: provider},
			CertChecker:         registrysvc.NewDeliveryService(db, d.DeploymentID),
			DIDs:                resolver,
			Policy:              bundle,
			SignatureCache:      sigCache,
			DeploymentID:        d.DeploymentID,
			ServiceDID:          fx.Identities["C"].ID,
			Audience:            defaultAudience,
			SupplierID:          defaultSupplierID,
			VerifierID:          runID + "-" + instID,
			OnDecisionCommitted: tr.recordTiming,
		})
		if err != nil {
			return fmt.Errorf("create gateway server %s: %w", instID, err)
		}
		tr.server = srv
		trackers = append(trackers, tr)
	}

	// Set Q800 catalog price and NORMAL trusted context.
	if err := gateway.SetCatalogPrice(ctx, db, d.DeploymentID, gateway.DefaultProductID, gateway.DefaultProductPriceMinor); err != nil {
		return fmt.Errorf("set Q800 catalog price: %w", err)
	}
	if err := ensureNormalContext(trackers[0].server.Handler(), task.ID, minExp); err != nil {
		return fmt.Errorf("set NORMAL context: %w", err)
	}

	// Use real deterministic wallet to request a real Q800 quote for B1.
	wallet, err := platformrt.BuildWallet(ctx, inst, d, fx, db, trackers[0].server.Handler())
	if err != nil {
		return fmt.Errorf("build deterministic wallet: %w", err)
	}
	quoteOut, err := wallet.RequestQuote(ctx, agent.RequestQuoteInput{
		Actor:             "B1",
		GrantID:           g2.ID,
		TaskID:            task.ID,
		AuthorizationMode: authMode,
		ProductID:         gateway.DefaultProductID,
		Quantity:          1,
		IdempotencyKey:    runID + "-q800",
	})
	if err != nil || quoteOut.Decision != "ALLOW" || quoteOut.QuoteID == "" || quoteOut.TotalAmountMinor != 80000 {
		return fmt.Errorf("prepare Q800 quote failed: err=%v out=%+v", err, quoteOut)
	}

	// Load immutable signed material for lock-free concurrent probing per instance.
	mat, err := loadProbeMaterial(inst, d.DeploymentID, fx, task, g0, g1, g2, quoteOut.QuoteID)
	if err != nil {
		return fmt.Errorf("load probe material: %w", err)
	}

	var recordsMu sync.Mutex
	var records []probeSlotRecord
	appendRecord := func(r probeSlotRecord) {
		recordsMu.Lock()
		records = append(records, r)
		recordsMu.Unlock()
	}

	// Warm-up: verify at least one real Q800 order succeeds on EVERY gateway instance before revocation.
	for _, tr := range trackers {
		warmKey := fmt.Sprintf("e6-%s-warmup", tr.id)
		rec := executeOrderProbe(ctx, tr, mat, "warmup", 0, time.Now().UTC().UnixNano(), nil, warmKey)
		appendRecord(rec)
		if rec.Disposition != "allowed" || rec.OrderID == "" {
			return fmt.Errorf("warm-up order failed on %s: disposition=%s status=%v code=%s reason=%s",
				tr.id, rec.Disposition, rec.HTTPStatus, rec.Code, rec.UnobservedReason)
		}
	}
	emitEvent("warmup_complete", time.Now().UTC(), map[string]any{"quoteId": quoteOut.QuoteID, "instances": len(trackers)})

	// Launch planned periodic probing on every instance.
	probeCtx, cancelProbing := context.WithCancel(ctx)
	var probeWG sync.WaitGroup
	for _, tr := range trackers {
		tr := tr
		probeWG.Add(1)
		go func() {
			defer probeWG.Done()
			runInstanceProber(probeCtx, tr, mat, cfg.detectInterval, appendRecord)
		}()
	}

	// Wait pre-revocation baseline, then revoke G1 as U with original txID.
	select {
	case <-time.After(cfg.revokeAfter):
	case <-ctx.Done():
		cancelProbing()
		probeWG.Wait()
		return ctx.Err()
	}

	emitEvent("revocation_submit_start", time.Now().UTC(), map[string]any{"grantId": g1.ID, "role": "U"})
	revEvent, revErr := inst.RevokeGrant(ctx, db, d, runID+"-revoke-g1", "U", g1.ID, "E6 short-run revocation")
	if revErr != nil {
		cancelProbing()
		probeWG.Wait()
		return fmt.Errorf("revoke G1: %w", revErr)
	}
	revBlockAtomic.Store(int64(revEvent.BlockNumber))
	emitEvent("revocation_valid", revEvent.ValidObservedAt, revEvent)

	// Continue probing for configured post-revocation duration.
	select {
	case <-time.After(cfg.duration):
	case <-ctx.Done():
	}
	cancelProbing()
	probeWG.Wait()

	// Resolve t_apply for block r and t_adopt,j for each instance.
	applyMu.Lock()
	tApply, hasApply := blockAppliedAt[revEvent.BlockNumber]
	applyMu.Unlock()
	var tApplyNs *int64
	if hasApply {
		v := tApply.UTC().UnixNano()
		tApplyNs = &v
	}

	// Enrich every probe record from PostgreSQL decisions & fabric_version G1 status.
	enrichCtx, enrichCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer enrichCancel()
	if err := enrichProbeRecords(enrichCtx, db, d.DeploymentID, g1.ID, records); err != nil {
		return fmt.Errorf("enrich probe records from DB: %w", err)
	}

	// Sort records deterministically by instance, phase, seq.
	sort.Slice(records, func(i, j int) bool {
		if records[i].InstanceID != records[j].InstanceID {
			return records[i].InstanceID < records[j].InstanceID
		}
		if records[i].Phase != records[j].Phase {
			return records[i].Phase == "warmup"
		}
		return records[i].Seq < records[j].Seq
	})

	// Write revocations.csv
	if err := writeRevocationsCSV(filepath.Join(cfg.out, "revocations.csv"), runID, authMode, cfg, revEvent, tApplyNs, trackers, clockResNs); err != nil {
		return err
	}
	// Write requests.csv
	if err := writeRequestsCSV(filepath.Join(cfg.out, "requests.csv"), runID, authMode, cfg.configuration, clockResNs, records); err != nil {
		return err
	}

	// Write summary.json
	acct := accountProbeRecords(records)
	instSummary := map[string]any{}
	for _, tr := range trackers {
		adoptAt, adoptH := tr.resolveFirstAdopt(int64(revEvent.BlockNumber))
		var adoptAtNs *int64
		if adoptAt != nil {
			v := adoptAt.UTC().UnixNano()
			adoptAtNs = &v
		}
		instSummary[tr.id] = map[string]any{
			"probeRole":   tr.probeRole,
			"tAdoptNs":    adoptAtNs,
			"adoptBlockH": adoptH,
		}
	}
	finishedAt := time.Now().UTC()
	summary := map[string]any{
		"runId":             runID,
		"experiment":        "E6",
		"status":            "PASS",
		"stage":             "execution",
		"stateSource":       state.SourceFabric,
		"deploymentId":      d.DeploymentID,
		"mode":              authMode,
		"modeShort":         modeShort,
		"configuration":     cfg.configuration,
		"startedAt":         startedAt.Format(time.RFC3339Nano),
		"finishedAt":        finishedAt.Format(time.RFC3339Nano),
		"clockTimebase":     clockTimebaseHostUTC,
		"clockResolutionNs": clockResNs,
		"revocation": map[string]any{
			"grantId":        g1.ID,
			"txId":           revEvent.TxID,
			"blockNumberR":   revEvent.BlockNumber,
			"blockHash":      revEvent.BlockHash,
			"txIndex":        revEvent.TxIndex,
			"validationCode": revEvent.ValidationCode,
			"tSubmitNs":      revEvent.SubmittedAt.UnixNano(),
			"tValidNs":       revEvent.ValidObservedAt.UnixNano(),
			"tApplyNs":       tApplyNs,
		},
		"instances":         instSummary,
		"requestAccounting": acct,
	}
	if ctx.Err() != nil {
		summary["status"] = "ABORTED"
		summary["error"] = ctx.Err().Error()
	}
	if err := harness.WriteJSON(filepath.Join(cfg.out, "summary.json"), summary); err != nil {
		return err
	}
	return ctx.Err()
}

func runInstanceProber(ctx context.Context, tr *instanceTracker, mat *probeMaterial, interval time.Duration, record func(probeSlotRecord)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Allow up to 4 concurrent probes per instance so 20ms cadence is maintained;
	// if all slots are busy when a tick fires, record a missed_probe_slot.
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var seq int64
	var lastSentNs int64

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case tickTime := <-ticker.C:
			seq++
			curSeq := seq
			plannedNs := tickTime.UTC().UnixNano()
			select {
			case sem <- struct{}{}:
				var actualInterval *int64
				if lastSentNs > 0 {
					d := plannedNs - lastSentNs
					actualInterval = &d
				}
				lastSentNs = plannedNs
				wg.Add(1)
				go func(s int64, pNs int64, aInt *int64) {
					defer wg.Done()
					defer func() { <-sem }()
					key := fmt.Sprintf("e6-%s-%06d", tr.id, s)
					rec := executeOrderProbe(ctx, tr, mat, "probe", s, pNs, aInt, key)
					record(rec)
				}(curSeq, plannedNs, actualInterval)
			default:
				record(probeSlotRecord{
					Phase:            "probe",
					InstanceID:       tr.id,
					ProbeRole:        tr.probeRole,
					Seq:              curSeq,
					PlannedAtNs:      plannedNs,
					IdempotencyKey:   fmt.Sprintf("e6-%s-%06d", tr.id, curSeq),
					Disposition:      "missed",
					UnobservedReason: "missed_probe_slot",
				})
			}
		}
	}
}

func applyProbeLease(rec *probeSlotRecord, lease state.ProbeLease) {
	pb := int64(lease.ProbeBlock)
	rec.ProbeTxID = lease.TxID
	rec.ProbeBlock = &pb
	if !lease.SentAt.IsZero() {
		v := lease.SentAt.UTC().UnixNano()
		rec.ProbeSentAtNs = &v
	}
	if !lease.Deadline.IsZero() {
		v := lease.Deadline.UTC().UnixNano()
		rec.ProbeDeadlineNs = &v
	}
	sm := lease.SentMonoNs
	dm := lease.DeadlineMonoNs
	rec.ProbeSentMonoNs = &sm
	rec.ProbeDeadlineMono = &dm
	if lease.CheckedMonoNs != 0 {
		cm := lease.CheckedMonoNs
		rec.ProbeCheckedMonoNs = &cm
	}
}

func applyDecisionTiming(rec *probeSlotRecord, dt gateway.DecisionTiming) {
	dNs := dt.DecisionAt.UTC().UnixNano()
	cNs := dt.CommittedAt.UTC().UnixNano()
	dSec := dt.DecisionAtSec
	bn := dt.BlockNumber
	pb := dt.ProbeBlock
	psNs := dt.ProbeSentAt.UTC().UnixNano()
	pdNs := dt.ProbeDeadline.UTC().UnixNano()
	sm := dt.ProbeSentMonoNs
	cm := dt.ProbeCheckedMonoNs
	dm := dt.ProbeDeadlineMonoNs
	rec.DecisionAtNs = &dNs
	rec.CommittedAtNs = &cNs
	rec.DecisionAtSec = &dSec
	rec.BlockNumber = &bn
	rec.BlockHash = dt.BlockHash
	rec.ProbeTxID = dt.ProbeTxID
	rec.ProbeBlock = &pb
	rec.ProbeSentAtNs = &psNs
	rec.ProbeDeadlineNs = &pdNs
	rec.ProbeSentMonoNs = &sm
	rec.ProbeCheckedMonoNs = &cm
	rec.ProbeDeadlineMono = &dm
}

func executeOrderProbe(parentCtx context.Context, tr *instanceTracker, mat *probeMaterial, phase string, seq int64, plannedNs int64, actualInterval *int64, idempKey string) probeSlotRecord {
	rec := probeSlotRecord{
		Phase:            phase,
		InstanceID:       tr.id,
		ProbeRole:        tr.probeRole,
		Seq:              seq,
		PlannedAtNs:      plannedNs,
		ActualIntervalNs: actualInterval,
		IdempotencyKey:   idempKey,
		Disposition:      "error",
	}

	callCtx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()

	orderReq := protocol.AccessRequest{
		SchemaVersion:     registry.Schema,
		DeploymentID:      mat.deploymentID,
		Actor:             mat.actorDID,
		PrincipalDomain:   "A",
		AuthorizationMode: mat.authMode,
		TaskID:            mat.taskID,
		Audience:          defaultAudience,
		Resource:          registry.ResourceOrders,
		Action:            registry.ActionOrderCreate,
		SupplierID:        defaultSupplierID,
		QuoteID:           &mat.quoteID,
		ProductID:         gateway.DefaultProductID,
		Quantity:          1,
		Currency:          gateway.DefaultCurrency,
		AmountMinor:       80000,
		IdempotencyKey:    idempKey,
	}
	reqHash, err := orderReq.Hash(false)
	if err != nil {
		rec.UnobservedReason = "request_hash_failed"
		return rec
	}

	// Step 1: Request fresh challenge.
	chalBody, _ := json.Marshal(gateway.ChallengeRequest{Actor: mat.actorDID, TaskID: mat.taskID, RequestHash: reqHash})
	chalHTTPReq := httptest.NewRequest(http.MethodPost, "/v1/auth/challenges", bytes.NewReader(chalBody)).WithContext(callCtx)
	chalHTTPReq.Header.Set("Content-Type", "application/json")
	chalResp := httptest.NewRecorder()
	tr.server.Handler().ServeHTTP(chalResp, chalHTTPReq)
	if chalResp.Code != http.StatusCreated {
		st := chalResp.Code
		rec.HTTPStatus = &st
		rec.RequestID = chalResp.Header().Get("X-Request-Id")
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			rec.Disposition = "timeout"
			rec.UnobservedReason = "challenge_timeout"
		} else {
			rec.UnobservedReason = fmt.Sprintf("challenge_http_%d", chalResp.Code)
		}
		return rec
	}
	var chal gateway.ChallengeResponse
	if err := json.Unmarshal(chalResp.Body.Bytes(), &chal); err != nil {
		rec.UnobservedReason = "challenge_decode_failed"
		return rec
	}
	rec.ChallengeID = chal.ChallengeID

	// Step 2: Assemble fresh KB-JWT signed access evidence package.
	pkg := protocol.AccessEvidencePackage{
		Request:             orderReq,
		TaskSpec:            mat.taskSpec,
		ChallengeID:         chal.ChallengeID,
		AncestorCredentials: mat.ancestors,
		Grants:              mat.grants,
		TrustPaths:          mat.trustPaths,
	}
	if _, _, err := protocol.AssembleAccessEvidencePackage(&pkg, mat.leafPresPrefix, mat.actorKeyID, mat.actorPriv, protocol.ChallengeContext{
		ChallengeID: chal.ChallengeID,
		Nonce:       chal.Nonce,
		Audience:    chal.Audience,
		IssuedAt:    chal.IssuedAt,
		ExpiresAt:   chal.ExpiresAt,
	}, time.Now().UTC().Unix(), false); err != nil {
		rec.UnobservedReason = "assemble_package_failed"
		return rec
	}
	execBody, _ := json.Marshal(pkg)

	// Step 3: Execute order against this gateway instance, capturing snapshot + decision timing + HTTP response.
	snapCap := &snapshotCapture{}
	execCtx := context.WithValue(callCtx, ctxKeySnapshotCapture{}, snapCap)
	execHTTPReq := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(execBody)).WithContext(execCtx)
	execHTTPReq.Header.Set("Content-Type", "application/json")

	submittedNs := time.Now().UTC().UnixNano()
	rec.SubmittedAtNs = &submittedNs
	execResp := httptest.NewRecorder()
	tr.server.Handler().ServeHTTP(execResp, execHTTPReq)
	respondedNs := time.Now().UTC().UnixNano()
	rec.RespondedAtNs = &respondedNs

	st := execResp.Code
	rec.HTTPStatus = &st
	rec.RequestID = execResp.Header().Get("X-Request-Id")

	if snap := snapCap.get(); snap != nil {
		bn := snap.BlockNumber
		rec.BlockNumber = &bn
		rec.BlockHash = snap.BlockHash
		applyProbeLease(&rec, snap.Probe)
	}

	var parsed struct {
		RequestID  string                `json:"requestId"`
		DecisionID *string               `json:"decisionId"`
		Code       string                `json:"code"`
		Order      *gateway.OrderPayload `json:"order"`
	}
	if json.Unmarshal(execResp.Body.Bytes(), &parsed) == nil {
		if parsed.RequestID != "" {
			rec.RequestID = parsed.RequestID
		}
		if parsed.DecisionID != nil {
			rec.DecisionID = *parsed.DecisionID
		}
		rec.Code = parsed.Code
		if parsed.Order != nil {
			rec.OrderID = parsed.Order.OrderID
		}
	}

	if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
		rec.Disposition = "timeout"
		rec.UnobservedReason = "execute_timeout"
		return rec
	}
	switch execResp.Code {
	case http.StatusOK:
		rec.Disposition = "allowed"
		rec.Outcome = "ALLOW"
	case http.StatusForbidden, http.StatusConflict, http.StatusUnauthorized, http.StatusServiceUnavailable:
		rec.Disposition = "denied"
		rec.Outcome = "DENY"
	default:
		rec.Disposition = "error"
		rec.UnobservedReason = fmt.Sprintf("unexpected_http_%d", execResp.Code)
	}

	if rec.DecisionID != "" {
		if dt, ok := tr.lookupTiming(rec.DecisionID); ok {
			applyDecisionTiming(&rec, dt)
		}
	} else if rec.Disposition == "denied" && rec.UnobservedReason == "" {
		rec.UnobservedReason = "precheck_deny_no_decision_row"
	}
	return rec
}

func enrichProbeRecords(ctx context.Context, db *pgxpool.Pool, deploymentID, g1ID string, records []probeSlotRecord) error {
	// Lookup G1 status per block number from fabric_version.
	g1Cache := map[int64]string{}
	g1StatusAt := func(blockNo int64) (string, error) {
		if st, ok := g1Cache[blockNo]; ok {
			return st, nil
		}
		var raw []byte
		err := db.QueryRow(ctx, `SELECT value FROM fabric_version WHERE deployment=$1 AND key=$2 AND block_no <= $3 ORDER BY block_no DESC, tx_index DESC LIMIT 1`,
			deploymentID, registry.Key("grant", g1ID), blockNo).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			g1Cache[blockNo] = "ABSENT"
			return "ABSENT", nil
		}
		if err != nil {
			return "", err
		}
		var g struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(raw, &g); err != nil {
			return "", err
		}
		g1Cache[blockNo] = g.Status
		return g.Status, nil
	}

	for idx := range records {
		r := &records[idx]
		if r.DecisionID != "" {
			var bn, pb, dSec int64
			var bHash, pTx string
			var dNs, psNs, pdNs, psMono, pcMono, pdMono *int64
			err := db.QueryRow(ctx, `SELECT block_number, block_hash, probe_tx_id, probe_block, decision_at, decision_at_ns,
				probe_sent_at_ns, probe_deadline_ns, probe_sent_mono_ns, probe_checked_mono_ns, probe_deadline_mono_ns
				FROM decisions WHERE deployment_id=$1 AND decision_id=$2`, deploymentID, r.DecisionID).Scan(
				&bn, &bHash, &pTx, &pb, &dSec, &dNs, &psNs, &pdNs, &psMono, &pcMono, &pdMono,
			)
			if err == nil {
				r.BlockNumber = &bn
				r.BlockHash = bHash
				r.ProbeTxID = pTx
				r.ProbeBlock = &pb
				r.DecisionAtSec = &dSec
				if dNs != nil {
					r.DecisionAtNs = dNs
				}
				if psNs != nil {
					r.ProbeSentAtNs = psNs
				}
				if pdNs != nil {
					r.ProbeDeadlineNs = pdNs
				}
				if psMono != nil {
					r.ProbeSentMonoNs = psMono
				}
				if pcMono != nil {
					r.ProbeCheckedMonoNs = pcMono
				}
				if pdMono != nil {
					r.ProbeDeadlineMono = pdMono
				}
			}
		}
		if r.BlockNumber != nil {
			st, err := g1StatusAt(*r.BlockNumber)
			if err != nil {
				return err
			}
			r.G1StatusAtBlock = st
		}
	}
	return nil
}

func loadProbeMaterial(inst *fabric.Instance, deploymentID string, fx *platformrt.Fixtures, task registry.Task, g0, g1, g2 registry.Grant, quoteID string) (*probeMaterial, error) {
	b1 := fx.Identities["B1"]
	b1Priv, err := fabric.LoadECPrivateKeyPEM(inst.PrivatePath("app", "B1.key.pem"))
	if err != nil {
		return nil, err
	}
	readReg := func(parts ...string) (string, error) {
		raw, err := os.ReadFile(inst.RegistryPath(parts...))
		return string(raw), err
	}
	b1SD, err := readReg("credentials", "B1.sdjwt")
	if err != nil {
		return nil, err
	}
	a1SD, err := readReg("credentials", "A1.sdjwt")
	if err != nil {
		return nil, err
	}
	uSD, err := readReg("credentials", "U.sdjwt")
	if err != nil {
		return nil, err
	}
	rootCredFile := "PA.sdjwt"
	rootCredID := fx.Credentials["PA"].ID
	if task.Mode == registry.RP {
		rootCredFile = "C.sdjwt"
		rootCredID = fx.Credentials["C"].ID
	}
	rootSD, err := readReg("credentials", rootCredFile)
	if err != nil {
		return nil, err
	}
	prefix := "bm"
	if task.Mode == registry.RP {
		prefix = "rp"
	}
	g0JWS, err := readReg("grants", prefix+"_g0.jws")
	if err != nil {
		return nil, err
	}
	g1JWS, err := readReg("grants", prefix+"_g1.jws")
	if err != nil {
		return nil, err
	}
	g2JWS, err := readReg("grants", prefix+"_g2.jws")
	if err != nil {
		return nil, err
	}
	var trustPaths []protocol.TrustPathEntry
	doms := []string{"A", "B"}
	if task.Mode == registry.RP {
		doms = []string{"A", "B", "C"}
	}
	for _, dom := range doms {
		certJWS, err := readReg("certifications", dom+".jws")
		if err != nil {
			return nil, err
		}
		trustPaths = append(trustPaths, protocol.TrustPathEntry{
			Issuer:              fx.Domains[dom].Issuers[0].ID,
			DomainCertification: certJWS,
		})
	}
	sort.Slice(trustPaths, func(i, j int) bool { return trustPaths[i].Issuer < trustPaths[j].Issuer })

	ancestors := []protocol.AncestorCredential{
		{CredentialID: rootCredID, Presentation: rootSD},
		{CredentialID: fx.Credentials["U"].ID, Presentation: uSD},
		{CredentialID: fx.Credentials["A1"].ID, Presentation: a1SD},
	}
	sort.Slice(ancestors, func(i, j int) bool { return ancestors[i].CredentialID < ancestors[j].CredentialID })

	return &probeMaterial{
		actorDID:       b1.ID,
		actorKeyID:     b1.KeyID,
		actorPriv:      b1Priv,
		leafPresPrefix: b1SD,
		taskID:         task.ID,
		taskSpec:       fx.ProcurementTaskSpec,
		authMode:       task.Mode,
		quoteID:        quoteID,
		ancestors:      ancestors,
		grants:         []string{g0JWS, g1JWS, g2JWS},
		trustPaths:     trustPaths,
		deploymentID:   deploymentID,
	}, nil
}

func e6ProcurementSetup(deploymentID, runID string, seed int) platformrt.ProcurementSetup {
	ids := func(mode string) platformrt.ProcurementPathIDs {
		ns := fmt.Sprintf("%s/e6/%s/%d/%s/", deploymentID, runID, seed, mode)
		return platformrt.ProcurementPathIDs{
			Task: registry.Digest([]byte(ns + "task")),
			G0:   registry.Digest([]byte(ns + "G0")),
			G1:   registry.Digest([]byte(ns + "G1")),
			G2:   registry.Digest([]byte(ns + "G2")),
		}
	}
	return platformrt.ProcurementSetup{
		Spec: protocol.TaskSpec{
			SupplierID:  defaultSupplierID,
			ProductID:   gateway.DefaultProductID,
			MaxQuantity: 1,
			Currency:    gateway.DefaultCurrency,
			Resources:   []string{registry.ResourceOrders, registry.ResourceQuotes},
			Actions:     []string{registry.ActionOrderCreate, registry.ActionQuoteRead},
			Description: "E6 revocation window procurement task",
		},
		RP: ids(registry.RP),
		BM: ids(registry.BM),
	}
}

func ensureNormalContext(handler http.Handler, taskID string, deadline int64) error {
	body, _ := json.Marshal(gateway.ContextUpdateRequest{
		ExpectedContextVersion: 0,
		SourceID:               "ctx-e6-c",
		ObservedAt:             time.Now().UTC().Unix() - 1,
		RiskLevel:              policy.RiskNormal,
		AccessDeadline:         deadline,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/contexts/"+taskID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return fmt.Errorf("POST /v1/contexts/%s HTTP %d: %s", taskID, rec.Code, rec.Body.String())
	}
	return nil
}

func buildRevocationCSVRows(runID, authMode string, cfg e6Config, rev *fabric.RevocationEvent, tApplyNs *int64, trackers []*instanceTracker, clockResNs int64) []revocationCSVRow {
	rows := make([]revocationCSVRow, 0, len(trackers))
	for _, tr := range trackers {
		adoptAt, adoptH := tr.resolveFirstAdopt(int64(rev.BlockNumber))
		var adoptAtNs *int64
		unobs := ""
		if adoptAt != nil {
			v := adoptAt.UTC().UnixNano()
			adoptAtNs = &v
		} else {
			unobs = "instance_did_not_adopt_r_during_window"
		}
		rows = append(rows, revocationCSVRow{
			RunID:               runID,
			Mode:                authMode,
			Configuration:       cfg.configuration,
			RevokedGrantID:      rev.GrantID,
			RevocationTxID:      rev.TxID,
			RevocationBlockR:    rev.BlockNumber,
			RevocationBlockHash: rev.BlockHash,
			TxIndex:             rev.TxIndex,
			ValidationCode:      rev.ValidationCode,
			TSubmitNs:           rev.SubmittedAt.UTC().UnixNano(),
			TValidNs:            rev.ValidObservedAt.UTC().UnixNano(),
			TApplyNs:            fmtIntPtr(tApplyNs),
			InstanceID:          tr.id,
			ProbeRole:           tr.probeRole,
			TAdoptNs:            fmtIntPtr(adoptAtNs),
			AdoptBlockH:         fmtIntPtr(adoptH),
			ProbeIntervalMs:     cfg.probeInterval.Milliseconds(),
			ProbeLifetimeMs:     cfg.probeLifetime.Milliseconds(),
			DetectIntervalMs:    cfg.detectInterval.Milliseconds(),
			ClockTimebase:       clockTimebaseHostUTC,
			ClockResolutionNs:   clockResNs,
			ClockErrorNs:        0,
			Status:              rev.Status,
			UnobservedReason:    unobs,
		})
	}
	return rows
}

func writeRevocationsCSV(path, runID, authMode string, cfg e6Config, rev *fabric.RevocationEvent, tApplyNs *int64, trackers []*instanceTracker, clockResNs int64) error {
	rows := buildRevocationCSVRows(runID, authMode, cfg, rev, tApplyNs, trackers, clockResNs)
	return harness.WriteCSV(path, rows)
}

func buildRequestCSVRows(runID, authMode, configuration string, clockResNs int64, records []probeSlotRecord) []requestCSVRow {
	rows := make([]requestCSVRow, 0, len(records))
	for _, r := range records {
		rows = append(rows, requestCSVRow{
			RunID:              runID,
			Mode:               authMode,
			Configuration:      configuration,
			Phase:              r.Phase,
			InstanceID:         r.InstanceID,
			ProbeRole:          r.ProbeRole,
			Seq:                r.Seq,
			PlannedAtNs:        r.PlannedAtNs,
			ActualIntervalNs:   fmtIntPtr(r.ActualIntervalNs),
			SubmittedAtNs:      fmtIntPtr(r.SubmittedAtNs),
			DecisionAtNs:       fmtIntPtr(r.DecisionAtNs),
			CommittedAtNs:      fmtIntPtr(r.CommittedAtNs),
			RespondedAtNs:      fmtIntPtr(r.RespondedAtNs),
			DecisionAtSec:      fmtIntPtr(r.DecisionAtSec),
			IdempotencyKey:     r.IdempotencyKey,
			RequestID:          r.RequestID,
			ChallengeID:        r.ChallengeID,
			DecisionID:         r.DecisionID,
			OrderID:            r.OrderID,
			HTTPStatus:         fmtIntValPtr(r.HTTPStatus),
			Code:               r.Code,
			Outcome:            r.Outcome,
			Disposition:        r.Disposition,
			BlockNumber:        fmtIntPtr(r.BlockNumber),
			BlockHash:          r.BlockHash,
			G1StatusAtBlock:    r.G1StatusAtBlock,
			ProbeTxID:          r.ProbeTxID,
			ProbeBlock:         fmtIntPtr(r.ProbeBlock),
			ProbeSentAtNs:      fmtIntPtr(r.ProbeSentAtNs),
			ProbeDeadlineNs:    fmtIntPtr(r.ProbeDeadlineNs),
			ProbeSentMonoNs:    fmtIntPtr(r.ProbeSentMonoNs),
			ProbeCheckedMonoNs: fmtIntPtr(r.ProbeCheckedMonoNs),
			ProbeDeadlineMono:  fmtIntPtr(r.ProbeDeadlineMono),
			ClockTimebase:      clockTimebaseHostUTC,
			ClockResolutionNs:  clockResNs,
			UnobservedReason:   r.UnobservedReason,
		})
	}
	return rows
}

func writeRequestsCSV(path, runID, authMode, configuration string, clockResNs int64, records []probeSlotRecord) error {
	rows := buildRequestCSVRows(runID, authMode, configuration, clockResNs, records)
	return harness.WriteCSV(path, rows)
}

func accountProbeRecords(records []probeSlotRecord) map[string]int {
	c := map[string]int{
		"warmup": 0, "planned": 0, "started": 0, "completed": 0,
		"missed": 0, "timeout": 0, "allowed": 0, "denied": 0, "error": 0,
	}
	for _, r := range records {
		if r.Phase == "warmup" {
			c["warmup"]++
			continue
		}
		c["planned"]++
		c[r.Disposition]++
		if r.Disposition != "missed" {
			c["started"]++
		}
		if r.Disposition == "allowed" || r.Disposition == "denied" || r.Disposition == "error" {
			c["completed"]++
		}
	}
	return c
}

func fmtIntPtr(v *int64) string {
	if v == nil {
		return "null"
	}
	return strconv.FormatInt(*v, 10)
}

func fmtIntValPtr(v *int) string {
	if v == nil {
		return "null"
	}
	return strconv.Itoa(*v)
}
