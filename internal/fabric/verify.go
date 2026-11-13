package fabric

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	api "graduation-design/internal/fabricapi"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/protobuf/proto"
)

type verdict struct {
	Name  string `json:"name"`
	Pass  bool   `json:"pass"`
	Error string `json:"error,omitempty"`
}

type verification struct {
	Run        string    `json:"runId"`
	Dir        string    `json:"evidenceDir"`
	Deployment string    `json:"deploymentId,omitempty"`
	Scope      string    `json:"scope"`
	Started    time.Time `json:"startedAt"`
	Finished   time.Time `json:"finishedAt"`
	Status     string    `json:"status"`
	Cases      []verdict `json:"cases"`
	Error      string    `json:"error,omitempty"`
}

type evidenceLog struct {
	mu   sync.Mutex
	file *os.File
	err  error
}

func (l *evidenceLog) event(name string, details any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = json.NewEncoder(l.file).Encode(map[string]any{"at": time.Now().UTC(), "event": name, "details": details})
	}
}

type acceptance struct {
	ctx      context.Context
	instance *instance
	d        *deployment
	j        journal
	v        view
	f        *fixtures
	p        *peerClient
	id       string
	dir      string
	log      *evidenceLog
}

func verify(ctx context.Context, dir, out string) (report *verification, err error) {
	run := "run-" + randomID()[:16]
	path := filepath.Join(out, run)
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, err
	}
	report = &verification{Run: run, Dir: path, Scope: "Fabric D0 verifiable protocol anchors, original transaction evidence and state-provider acceptance", Started: time.Now().UTC()}
	defer func() {
		report.Finished = time.Now().UTC()
		report.Status = "PASS"
		if err != nil {
			report.Status, report.Error = "FAIL", err.Error()
		}
		err = errors.Join(err, writeJSON(filepath.Join(path, "summary.json"), report))
	}()
	f, err := os.Create(filepath.Join(path, "events.jsonl"))
	if err != nil {
		return report, err
	}
	log := &evidenceLog{file: f}
	defer func() { err = errors.Join(err, log.err, f.Close()) }()
	log.event("start", map[string]any{"instance": dir, "runId": run})
	if err := ctx.Err(); err != nil {
		log.event("preflight_failed", err.Error())
		report.Cases = append(report.Cases, verdict{Name: "preflight", Error: err.Error()})
		return report, err
	}
	i, err := loadInstance(dir)
	if err != nil {
		return report, err
	}
	log.event("network", i.env)
	d, err := i.deploy(ctx, false)
	if err != nil {
		log.event("deploy_failed", err.Error())
		report.Cases = append(report.Cases, verdict{Name: "deployment", Error: err.Error()})
		return report, err
	}
	report.Deployment = d.DeploymentID
	log.event("deployment", d)
	if err := i.publicMaterials(path); err != nil {
		return report, err
	}
	db, err := i.database(ctx)
	if err != nil {
		return report, err
	}
	defer db.Close()
	if err := initSchema(ctx, db, operationsSchema+viewSchema); err != nil {
		return report, err
	}
	p, err := i.peer("c", "read")
	if err != nil {
		return report, err
	}
	defer p.close()
	a := acceptance{ctx: ctx, instance: i, d: d, j: journal{instance: i, deploymentID: d.DeploymentID, db: db}, v: view{db: db, d: d}, p: p, id: run, dir: path, log: log}
	defer func() {
		// Preserve already applied blocks even when the acceptance deadline was reached.
		c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		err = errors.Join(err, a.exportBlocks(c))
	}()
	seed, seedErr := i.seed(ctx, a.j, d)
	if seed != nil {
		err = writeJSON(filepath.Join(path, "seed.json"), seed)
	}
	if err = errors.Join(err, seedErr); err != nil {
		log.event("seed_failed", err.Error())
		report.Cases = append(report.Cases, verdict{Name: "fixtures", Error: err.Error()})
		return report, err
	}
	a.f = seed.fixtures
	if err := i.publicMaterials(path); err != nil {
		return report, err
	}
	cases := []struct {
		name string
		run  func() error
	}{
		{"channel-admission-and-bft-governance", a.channel},
		{"deployment-binding", a.deploymentBinding},
		{"initialization-resume", a.initializationResume},
		{"role-scope-and-credential-versions", a.roles},
		{"credential-validity-boundaries", a.credentialValidityBoundaries},
		{"rp-task-and-path-constraints", a.path},
		{"revocation-and-replacement", a.mutations},
		{"proposal-window-and-delayed-commit", a.timestamps},
		{"durable-operation-mvcc-and-dependency", a.concurrency},
		{"lost-response-and-original-replay", a.replay},
		{"block-validation-and-postgresql-atomicity", a.viewFaults},
		{"fixed-snapshot-history-and-probe-limits", a.snapshotAndProbes},
		{"shared-view-concurrent-checkpoint", a.sharedViewResume},
		{"checkpoint-query-outage-and-recovery", a.checkpointQueryOutage},
		{"sorter-and-peer-failures", a.networkFaults},
		{"chaincode-outage-and-recovery", a.chaincodeOutage},
		{"restart-keeps-checkpoint", a.restart},
		{"protocol-encoding-and-vectors", a.protocolVectors},
		{"did-web-and-context-pinning", a.protocolDIDAndContext},
		{"verifiable-evidence-and-tamper-rejection", a.protocolEvidence},
	}
	for _, test := range cases {
		log.event("case_start", test.name)
		testErr := ctx.Err()
		if testErr == nil {
			testErr = test.run()
		}
		entry := verdict{Name: test.name, Pass: testErr == nil}
		if testErr != nil {
			entry.Error = testErr.Error()
			err = errors.Join(err, fmt.Errorf("%s: %w", test.name, testErr))
		}
		report.Cases = append(report.Cases, entry)
		log.event("case_result", entry)
	}
	return report, err
}

func (i *instance) publicMaterials(out string) error {
	dest := filepath.Join(out, "materials")
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}
	files := map[string]string{
		"compose.yaml": "infra/fabric/compose.yaml", "channel.sh": "infra/fabric/channel.sh", "network.sh": "infra/fabric/network.sh",
		"tools.sh": "infra/fabric/tools.sh", "go.mod": "go.mod", "go.sum": "go.sum",
	}
	for _, f := range []string{"configtx.yaml", "cryptogen.yaml", "genesis.pb", "network.env"} {
		files[f] = filepath.Join(i.dir, f)
	}
	for _, f := range []string{"approval.json", "bootstrap.json", "definition.json", "deployment.json", "initialization.json", "a.tar.gz", "b.tar.gz", "c.tar.gz"} {
		files[f] = i.registryPath(f)
	}
	for _, org := range []string{"a", "b", "c", "d"} {
		files["orderer-"+org+".json"] = filepath.Join(i.dir, "orderer-"+org+".json")
	}
	for name, src := range files {
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dest, name), b, 0644); err != nil {
			return err
		}
	}
	protoFiles, err := collectRegistryPublicFiles(filepath.Join(i.dir, "registry"))
	if err != nil {
		return err
	}
	for rel, src := range protoFiles {
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, "protocol", rel)
		if err := writePublicFile(target, b); err != nil {
			return err
		}
	}
	if _, err := scanDirForPrivateKeys(out); err != nil {
		return err
	}
	return nil
}

func (a acceptance) exportBlocks(ctx context.Context) error {
	dest := filepath.Join(a.dir, "blocks")
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}
	index, err := os.Create(filepath.Join(a.dir, "blocks.jsonl"))
	if err != nil {
		return err
	}
	defer index.Close()
	rows, err := a.v.db.Query(ctx, "SELECT data FROM fabric_block WHERE deployment=$1 ORDER BY block_no", a.d.DeploymentID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		pb, err := decode(raw, &cb.Block{})
		if err != nil {
			return err
		}
		b, err := parseBlock(pb)
		if err != nil {
			return err
		}
		txs := make([]map[string]any, 0, len(b.Transactions))
		for _, t := range b.Transactions {
			var keys []string
			for _, w := range t.Writes {
				keys = append(keys, w.Key)
			}
			txs = append(txs, map[string]any{"txId": t.ID, "index": t.Index, "validationCode": t.Code.String(), "chaincode": t.Chaincode, "writeKeys": keys})
		}
		name := fmt.Sprintf("%06d.pb", b.Number)
		if err := os.WriteFile(filepath.Join(dest, name), raw, 0644); err != nil {
			return err
		}
		if err := json.NewEncoder(index).Encode(map[string]any{"point": b.point, "parentHash": b.Parent, "transactions": txs, "raw": "blocks/" + name}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (a acceptance) op(label, role, method string, value any, expected string) (*operation, error) {
	op, err := a.j.write(a.ctx, a.id+"/"+label, role, method, payload(value))
	a.log.event("operation", op)
	if err != nil {
		return op, err
	}
	return op, expectOperation(op, expected)
}

func expectOperation(op *operation, expected string) error {
	if op == nil {
		return fmt.Errorf("expected operation %s", expected)
	}
	switch expected {
	case "VALID":
		if op.Status == "CONFIRMED" && op.Commit != nil && op.Commit.Code == "VALID" {
			return nil
		}
	case "PENDING":
		if op.Status == "PENDING" && op.Commit == nil {
			return nil
		}
	default:
		if op.Status == "FAILED" && ((op.Commit != nil && op.Commit.Code == expected) ||
			(op.Commit == nil && op.FailureCode != nil && *op.FailureCode == expected)) {
			return nil
		}
	}
	failure := ""
	if op.FailureCode != nil {
		failure = *op.FailureCode
	}
	return fmt.Errorf("%s: expected %s, got %s at %s (failure=%s, commit=%+v, %s)",
		op.Key, expected, op.Status, op.Stage, failure, op.Commit, op.Observation)
}

func (a acceptance) prepared(label, role, method string, value any, orgs ...string) (*operation, error) {
	op, err := a.j.prepare(a.ctx, a.id+"/"+label, role, method, payload(value), orgs...)
	a.log.event("prepared", op)
	if err == nil && (op.Status != "PENDING" || len(op.Signed) == 0 || op.BroadcastAt != nil) {
		err = fmt.Errorf("expected signed unbroadcast transaction: %s (%s)", label, op.Observation)
	}
	return op, err
}

func (a acceptance) finish(op *operation, expected string) (*operation, error) {
	op, err := a.j.recover(a.ctx, op.Key, nil)
	a.log.event("operation", op)
	if err != nil {
		return op, err
	}
	return op, expectOperation(op, expected)
}

func (a acceptance) cloneGrant(label string) api.Grant {
	g := a.f.G1
	g.ID = api.Digest([]byte(a.id + "/" + label))
	g.Digest = api.Digest([]byte("synthetic grant " + g.ID))
	return g
}

func revokeOf(g api.Grant) api.Mutation {
	revision := g.Revision
	if revision == 0 {
		revision = 1
	}
	return api.Mutation{Bound: g.Bound, ID: g.ID, ExpectedRevision: revision, ExpectedDigest: g.Digest}
}

func ledgerRecord[T any](ctx context.Context, p *peerClient, kind, id string) (T, error) {
	var v T
	b, err := p.direct(ctx, api.Registry, "Read", api.Key(kind, id))
	if err == nil {
		err = json.Unmarshal(b, &v)
	}
	return v, err
}

func (a acceptance) absent(kind, id string) error {
	_, err := a.p.direct(a.ctx, api.Registry, "Read", api.Key(kind, id))
	if !missingRegistryRecord(err) {
		return fmt.Errorf("expected absent %s/%s: %v", kind, id, err)
	}
	return nil
}

func (a acceptance) observedRaw(n uint64) (*cb.Block, error) {
	b, err := a.p.getBlock(a.ctx, n)
	if err != nil {
		return nil, err
	}
	return proto.CloneOf(b.raw), nil
}

func newRuntime(a acceptance) *online {
	return &online{view: a.v, instance: a.instance, role: "probe1", interval: api.ProbeInterval, timeLimit: api.ProbeLifetime, observe: a.log.event}
}
