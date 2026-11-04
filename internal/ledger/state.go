package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Clock interface {
	Wall() time.Time
	Mono() time.Duration
}
type SystemClock struct{ start time.Time }

func NewSystemClock() *SystemClock         { return &SystemClock{start: time.Now()} }
func (c *SystemClock) Wall() time.Time     { return time.Now().UTC() }
func (c *SystemClock) Mono() time.Duration { return time.Since(c.start) }

type StateQuery struct {
	Method string        `json:"method"`
	ID     common.Hash   `json:"id"`
	Block  string        `json:"block"`
	Data   hexutil.Bytes `json:"data"`
}
type Snapshot struct {
	Mode           string                                `json:"mode"`
	DeploymentID   string                                `json:"deploymentId"`
	GrantID        common.Hash                           `json:"grantId"`
	Header         *Header                               `json:"header"`
	CheckedAt      time.Time                             `json:"checkedAt"`
	Fresh          *bool                                 `json:"fresh,omitempty"`
	Root           *RootRecord                           `json:"root"`
	Grants         map[string]*GrantRecord               `json:"grants"`
	Tasks          map[string]*TaskRecord                `json:"tasks"`
	Identities     map[string]*IdentityRecord            `json:"identities"`
	Credentials    map[string]*CredentialRecord          `json:"credentials"`
	Domains        map[string]*DomainRecord              `json:"domains"`
	Certifications map[string]*DomainCertificationRecord `json:"certifications"`
	Queries        []StateQuery                          `json:"queries"`
}

type StateFailure struct {
	Code      string    `json:"code"`
	Detail    string    `json:"detail"`
	Header    *Header   `json:"header,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

func (e *StateFailure) Error() string { return e.Code + ": " + e.Detail }

type HeadCheckpoint struct {
	DeploymentID string `json:"deploymentId"`
	Header       Header `json:"header"`
}

type StateReader struct {
	mu              sync.Mutex
	Client          *ethclient.Client
	Deployment      *Deployment
	Dir             string
	Clock           Clock
	MaxAge          time.Duration
	FutureTolerance time.Duration
	lastWall        int64
	budgets         map[common.Hash]time.Duration
	boundID         string
}

func NewStateReader(client *ethclient.Client, d *Deployment, dir string, clock Clock) *StateReader {
	if clock == nil {
		clock = NewSystemClock()
	}
	return &StateReader{Client: client, Deployment: d, Dir: dir, Clock: clock, MaxAge: 5 * time.Second, FutureTolerance: time.Second, budgets: map[common.Hash]time.Duration{}, boundID: d.DeploymentID}
}

func (r *StateReader) failure(code, detail string, h *Header) error {
	return &StateFailure{code, detail, h, r.Clock.Wall()}
}
func (r *StateReader) wrapped(err error, h *Header) error {
	code := "STATE_QUERY_FAILED"
	for _, candidate := range []string{"DEPLOYMENT_MISMATCH", "BLOCK_HASH_CHANGED", "BLOCK_UNAVAILABLE"} {
		if strings.HasPrefix(err.Error(), candidate) {
			code = candidate
			break
		}
	}
	return r.failure(code, err.Error(), h)
}

// Revalidate permits a deliberate clock correction, retaining all existing block budgets.
// The next Check still verifies deployment, persisted height/hash and freshness.
func (r *StateReader) Revalidate() { r.mu.Lock(); defer r.mu.Unlock(); r.lastWall = 0 }

func (r *StateReader) fresh(h *Header) error {
	now := r.Clock.Wall().UnixNano()
	if r.lastWall != 0 && now < r.lastWall {
		return r.failure("CLOCK_ROLLED_BACK", "wall clock moved backwards", h)
	}
	r.lastWall = now
	if uint64(h.Timestamp) > uint64(^uint64(0)>>1)/uint64(time.Second) {
		return r.failure("BLOCK_TIME_FUTURE", "block timestamp exceeds clock range", h)
	}
	age := time.Duration(now - int64(h.Timestamp)*int64(time.Second))
	if age < -r.FutureTolerance {
		return r.failure("BLOCK_TIME_FUTURE", "block timestamp exceeds future tolerance", h)
	}
	if age > r.MaxAge {
		return r.failure("STATE_STALE", fmt.Sprintf("block age %s exceeds %s", age, r.MaxAge), h)
	}
	mono := r.Clock.Mono()
	deadline, seen := r.budgets[h.Hash]
	if !seen {
		remaining := r.MaxAge
		if age > 0 {
			remaining -= age
		}
		if remaining < 0 {
			remaining = 0
		}
		deadline = mono + remaining
		r.budgets[h.Hash] = deadline
	}
	if mono > deadline {
		return r.failure("STATE_STALE", "first-seen monotonic budget exhausted", h)
	}
	return nil
}

func (r *StateReader) checkpoint(ctx context.Context, h *Header) error {
	path := filepath.Join(r.Dir, "heads", r.boundID+".json")
	b, err := os.ReadFile(path)
	if err == nil {
		var prior HeadCheckpoint
		if err = json.Unmarshal(b, &prior); err != nil {
			return r.failure("READER_NOT_READY", "checkpoint is damaged", h)
		}
		if prior.DeploymentID != r.boundID || prior.Header.Hash == (common.Hash{}) {
			return r.failure("DEPLOYMENT_MISMATCH", "checkpoint binding mismatch", h)
		}
		if h.Number < prior.Header.Number {
			return r.failure("HEAD_REGRESSION", "candidate is below highest seen head", h)
		}
		if h.Number == prior.Header.Number {
			if h.Hash != prior.Header.Hash || h.Timestamp != prior.Header.Timestamp {
				return r.failure("HEAD_CONFLICT", "different header at highest seen height", h)
			}
		} else {
			old, err := ReadHeader(ctx, r.Client, new(big.Int).SetUint64(uint64(prior.Header.Number)))
			if err != nil {
				return r.wrapped(err, h)
			}
			if old.Hash != prior.Header.Hash || old.Timestamp != prior.Header.Timestamp {
				return r.failure("HEAD_CONFLICT", "persisted checkpoint no longer matches node", h)
			}
		}
	} else if !os.IsNotExist(err) {
		return r.wrapped(err, h)
	}
	if err = durableJSON(path, HeadCheckpoint{r.boundID, *h}); err != nil {
		return r.wrapped(err, h)
	}
	return nil
}

func (r *StateReader) Check(ctx context.Context, grant common.Hash) (*Snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Deployment.DeploymentID != r.boundID {
		return nil, r.failure("DEPLOYMENT_MISMATCH", "reader deployment changed", nil)
	}
	headDir := filepath.Join(r.Dir, "heads")
	if err := os.MkdirAll(headDir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(headDir, "reader.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, r.failure("READER_NOT_READY", "another reader is updating the checkpoint", nil)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	h, err := ReadHeader(ctx, r.Client, nil)
	if err != nil {
		return nil, r.wrapped(err, nil)
	}
	if err = ValidateDeploymentAt(ctx, r.Client, r.Deployment, h); err != nil {
		return nil, r.wrapped(err, h)
	}
	if err = r.checkpoint(ctx, h); err != nil {
		return nil, err
	}
	if err = r.fresh(h); err != nil {
		return nil, err
	}
	s, err := r.assemble(ctx, grant, h, "online")
	if err != nil {
		return nil, r.wrapped(err, h)
	}
	if err = r.fresh(h); err != nil {
		return nil, err
	}
	fresh := true
	s.Fresh = &fresh
	s.CheckedAt = r.Clock.Wall()
	return s, nil
}

func (r *StateReader) Inspect(ctx context.Context, grant common.Hash, number *big.Int) (*Snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if number == nil || number.Sign() < 0 {
		return nil, r.failure("INVALID_BLOCK", "explicit nonnegative historical block required", nil)
	}
	h, err := ReadHeader(ctx, r.Client, number)
	if err != nil {
		return nil, r.wrapped(err, nil)
	}
	if err = ValidateDeploymentAt(ctx, r.Client, r.Deployment, h); err != nil {
		return nil, r.wrapped(err, h)
	}
	s, err := r.assemble(ctx, grant, h, "historical")
	if err != nil {
		return nil, r.wrapped(err, h)
	}
	return s, nil
}

type dependency struct {
	method string
	id     common.Hash
}
type snapshotBuilder struct {
	reader   *StateReader
	snapshot *Snapshot
	ctx      context.Context
	block    *big.Int
}

func fixedRecord[T any](b *snapshotBuilder, method string, id common.Hash) (value *T, err error) {
	defer func() {
		if p := recover(); p != nil {
			value = nil
			err = fmt.Errorf("malformed %s ABI output", method)
		}
	}()
	var args []any
	if method != "getRoot" {
		args = []any{id}
	}
	a, err := abi.JSON(strings.NewReader(string(b.reader.Deployment.ABI)))
	if err != nil {
		return nil, err
	}
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	b.snapshot.Queries = append(b.snapshot.Queries, StateQuery{method, id, hexutil.EncodeBig(b.block), data})
	v, err := ReadView(b.ctx, b.reader.Client, b.reader.Deployment, b.block, method, args...)
	if err != nil {
		return nil, err
	}
	if len(v) != 1 {
		return nil, fmt.Errorf("missing %s output", method)
	}
	return abi.ConvertType(v[0], new(T)).(*T), nil
}

func (r *StateReader) assemble(ctx context.Context, grant common.Hash, h *Header, mode string) (*Snapshot, error) {
	s := &Snapshot{Mode: mode, DeploymentID: r.boundID, GrantID: grant, Header: h, CheckedAt: r.Clock.Wall(), Grants: map[string]*GrantRecord{}, Tasks: map[string]*TaskRecord{}, Identities: map[string]*IdentityRecord{}, Credentials: map[string]*CredentialRecord{}, Domains: map[string]*DomainRecord{}, Certifications: map[string]*DomainCertificationRecord{}}
	b := &snapshotBuilder{r, s, ctx, new(big.Int).SetUint64(uint64(h.Number))}
	root, err := fixedRecord[RootRecord](b, "getRoot", common.Hash{})
	if err != nil {
		return nil, err
	}
	s.Root = root
	queue := []dependency{{"getGrant", grant}, {"getIdentity", r.Deployment.ResourceOwner}}
	seen := map[dependency]bool{}
	grantCount := 0
	add := func(method string, id common.Hash) { queue = append(queue, dependency{method, id}) }
	for len(queue) > 0 {
		dep := queue[0]
		queue = queue[1:]
		if seen[dep] {
			if dep.method == "getGrant" {
				return nil, fmt.Errorf("grant path cycle")
			}
			continue
		}
		seen[dep] = true
		if len(seen) > 256 {
			return nil, fmt.Errorf("dependency limit exceeded")
		}
		key := dep.id.Hex()
		switch dep.method {
		case "getGrant":
			grantCount++
			if grantCount > 33 {
				return nil, fmt.Errorf("grant path depth exceeded")
			}
			v, err := fixedRecord[GrantRecord](b, dep.method, dep.id)
			if err != nil {
				return nil, err
			}
			if v.Grant.GrantId != dep.id || v.Grant.DeploymentId != common.HexToHash(r.boundID) {
				return nil, fmt.Errorf("grant binding mismatch")
			}
			s.Grants[key] = v
			if v.Grant.ParentId != (common.Hash{}) {
				add("getGrant", v.Grant.ParentId)
			}
			add("getTask", v.Grant.TaskId)
			add("getIdentity", v.Grant.Issuer)
			add("getIdentity", v.Grant.Grantee)
			add("getCredential", v.Grant.IssuerCredentialId)
			add("getCredential", v.Grant.GranteeCredentialId)
		case "getTask":
			v, err := fixedRecord[TaskRecord](b, dep.method, dep.id)
			if err != nil {
				return nil, err
			}
			if v.Task.TaskId != dep.id || v.Task.DeploymentId != common.HexToHash(r.boundID) {
				return nil, fmt.Errorf("task binding mismatch")
			}
			s.Tasks[key] = v
			add("getIdentity", v.Task.Creator)
			add("getCredential", v.Task.CreatorCredentialId)
		case "getIdentity":
			v, err := fixedRecord[IdentityRecord](b, dep.method, dep.id)
			if err != nil {
				return nil, err
			}
			if hashID(v.Identity.SubjectId) != dep.id {
				return nil, fmt.Errorf("identity binding mismatch")
			}
			s.Identities[key] = v
			add("getDomain", hashID(v.Identity.DomainId))
		case "getCredential":
			v, err := fixedRecord[CredentialRecord](b, dep.method, dep.id)
			if err != nil {
				return nil, err
			}
			if hashID(v.Credential.CredentialId) != dep.id {
				return nil, fmt.Errorf("credential binding mismatch")
			}
			s.Credentials[key] = v
			add("getIdentity", hashID(v.Credential.Issuer))
			add("getIdentity", hashID(v.Credential.Subject))
		case "getDomain":
			v, err := fixedRecord[DomainRecord](b, dep.method, dep.id)
			if err != nil {
				return nil, err
			}
			if hashID(v.DomainId) != dep.id || v.CurrentCertificationId == (common.Hash{}) {
				return nil, fmt.Errorf("domain/current certification missing")
			}
			s.Domains[key] = v
			add("getDomainCertification", v.CurrentCertificationId)
			add("getIdentity", hashID(v.DomainDid))
			for _, issuer := range v.IdentityIssuers {
				add("getIdentity", hashID(issuer))
			}
		case "getDomainCertification":
			v, err := fixedRecord[DomainCertificationRecord](b, dep.method, dep.id)
			if err != nil {
				return nil, err
			}
			if hashID(v.Certification.CertificationId) != dep.id {
				return nil, fmt.Errorf("certification binding mismatch")
			}
			s.Certifications[key] = v
			add("getDomain", hashID(v.Certification.DomainId))
			for _, issuer := range v.Certification.IdentityIssuers {
				add("getIdentity", hashID(issuer.Id))
			}
		default:
			return nil, fmt.Errorf("unknown dependency")
		}
	}
	end, err := ReadHeader(ctx, r.Client, b.block)
	if err != nil {
		return nil, err
	}
	if end.Hash != h.Hash || end.Timestamp != h.Timestamp {
		return nil, fmt.Errorf("BLOCK_HASH_CHANGED: fixed-height assembly")
	}
	return s, nil
}
