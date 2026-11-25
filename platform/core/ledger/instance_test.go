package ledger

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"grad/protocol"
	"grad/protocol/registry"
)

func TestOperationRejectedBeforeSigning(t *testing.T) {
	code := "ENDORSEMENT_REJECTED"
	now := time.Now()
	rejected := Operation{
		Status:      "FAILED",
		Stage:       "ENDORSE",
		FailureCode: &code,
		Observation: "incorrect timestamp",
		TxID:        registry.Digest([]byte("original")),
		Proposal:    []byte("signed proposal"),
	}
	assert.True(t, rejected.RejectedBeforeSigning())

	for _, tc := range []struct {
		name   string
		change func(*Operation)
	}{
		{"pending", func(op *Operation) { op.Status = "PENDING" }},
		{"commit stage", func(op *Operation) { op.Stage = "COMMIT" }},
		{"no rejection code", func(op *Operation) { op.FailureCode = nil }},
		{"no rejection observation", func(op *Operation) { op.Observation = "" }},
		{"no original proposal", func(op *Operation) { op.Proposal = nil }},
		{"signed transaction", func(op *Operation) { op.Signed = []byte("signed transaction") }},
		{"signing recorded", func(op *Operation) { op.SignedAt = &now }},
		{"broadcast recorded", func(op *Operation) { op.BroadcastAt = &now }},
		{"commit recorded", func(op *Operation) { op.Commit = &Outcome{Code: "MVCC_READ_CONFLICT"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := rejected
			tc.change(&op)
			assert.False(t, op.RejectedBeforeSigning())
		})
	}
}

func TestRegistrySourceDigestScope(t *testing.T) {
	// Real repo root digest must succeed regardless of cwd.
	realDigest, err := RegistrySourceDigest()
	require.NoError(t, err)
	assert.True(t, registry.IsDigest(realDigest))

	// Construct isolated synthetic repo layout to assert exact hashed file scope.
	root := t.TempDir()
	writeFile := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0644))
	}
	writeFile("chaincode/go.mod", "module grad/chaincode\n")
	writeFile("chaincode/go.sum", "sum-v1\n")
	writeFile("chaincode/registry/main.go", "package main\n")
	writeFile("chaincode/registry/main_test.go", "package main\n")
	writeFile("protocol/registry/types.go", "package registry\n")
	writeFile("protocol/registry/types_test.go", "package registry\n")
	writeFile("protocol/other.go", "package protocol\n")
	writeFile("platform/go.mod", "module grad/platform\n")

	base, err := registrySourceDigestAt(root)
	require.NoError(t, err)
	assert.True(t, registry.IsDigest(base))

	// Ignored files must NOT change digest.
	for _, ignored := range []string{
		"chaincode/registry/main_test.go",
		"protocol/registry/types_test.go",
		"protocol/other.go",
		"platform/go.mod",
	} {
		writeFile(ignored, "// mutated ignored file\n")
		got, err := registrySourceDigestAt(root)
		require.NoError(t, err)
		assert.Equal(t, base, got, "modifying %s must not change registrySourceDigest", ignored)
	}

	// Tracked files MUST change digest.
	for _, tracked := range []string{
		"chaincode/go.mod",
		"chaincode/go.sum",
		"chaincode/registry/main.go",
		"protocol/registry/types.go",
	} {
		orig, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(tracked)))
		require.NoError(t, err)
		writeFile(tracked, string(orig)+"// changed\n")
		got, err := registrySourceDigestAt(root)
		require.NoError(t, err)
		assert.NotEqual(t, base, got, "modifying %s must change registrySourceDigest", tracked)
		writeFile(tracked, string(orig))
	}
}

func TestBuildChaincodePackageDeterminism(t *testing.T) {
	cert := []byte("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n")
	approval := []byte(`{"deploymentId":"abc"}`)

	id1, data1, err := BuildChaincodePackage("a", cert, approval)
	require.NoError(t, err)
	id2, data2, err := BuildChaincodePackage("a", cert, approval)
	require.NoError(t, err)
	assert.Equal(t, id1, id2)
	assert.Equal(t, data1, data2)

	id3, data3, err := BuildChaincodePackage("a", cert, []byte(`{"deploymentId":"def"}`))
	require.NoError(t, err)
	assert.NotEqual(t, id1, id3)
	assert.NotEqual(t, data1, data3)
}

type stubEndorseError struct {
	st      *status.Status
	details []*gw.ErrorDetail
}

func (e *stubEndorseError) Error() string              { return e.st.Err().Error() }
func (e *stubEndorseError) GRPCStatus() *status.Status { return e.st }
func (e *stubEndorseError) Details() []*gw.ErrorDetail { return e.details }

func TestParseEndorsementFailureCanonicalCodes(t *testing.T) {
	makeEndorseErr := func(code codes.Code, msgs ...string) error {
		st := status.New(code, "rpc error: endorsement failed")
		details := make([]*gw.ErrorDetail, 0, len(msgs))
		for _, m := range msgs {
			details = append(details, &gw.ErrorDetail{Address: "peer-c:7051", MspId: "CMsp", Message: m})
		}
		return &stubEndorseError{st: st, details: details}
	}

	assert.Equal(t, registry.ErrCodeUnauthorized,
		ParseEndorsementFailure(makeEndorseErr(codes.Aborted, "chaincode response 500, UNAUTHORIZED")))
	assert.Equal(t, registry.ErrCodeInvalidStructure,
		ParseEndorsementFailure(makeEndorseErr(codes.Aborted, "chaincode response 500, INVALID_STRUCTURE")))
	assert.Equal(t, registry.ErrCodePurchasingAuthorityInvalid,
		ParseEndorsementFailure(makeEndorseErr(codes.Aborted, "chaincode response 500, PURCHASING_AUTHORITY_INVALID: mismatch")))
	assert.Equal(t, registry.ErrCodeAlreadyRevoked,
		ParseEndorsementFailure(makeEndorseErr(codes.Aborted, "chaincode response 500, ALREADY_REVOKED", "chaincode response 500, ALREADY_REVOKED")))

	// Conflicting canonical codes across endorsers collapse to ENDORSEMENT_REJECTED.
	assert.Equal(t, "ENDORSEMENT_REJECTED",
		ParseEndorsementFailure(makeEndorseErr(codes.Aborted, "chaincode response 500, UNAUTHORIZED", "chaincode response 500, INVALID_STATE")))

	// Legacy D0: prefix is NOT recognized; chaincode emits bare canonical codes only.
	assert.Equal(t, "", extractChaincodeErrorCode("chaincode response 500, D0:UNAUTHORIZED"))

	for _, code := range []string{registry.ErrCodeCommitInvalid, registry.ErrCodeOperationUnknown, registry.ErrCodeEndorsementRejected} {
		assert.True(t, registry.IsKnownCode(code))
		assert.Empty(t, extractChaincodeErrorCode("chaincode response 500, "+code))
	}

	// Transient transport errors remain PENDING (empty code).
	assert.Equal(t, "", ParseEndorsementFailure(status.Error(codes.Unavailable, "peer unreachable")))
	assert.Equal(t, "", ParseEndorsementFailure(status.Error(codes.Aborted, "insufficient peers available")))

	// Proposal timestamp rejection is deterministic ENDORSEMENT_REJECTED.
	assert.Equal(t, "ENDORSEMENT_REJECTED", ParseEndorsementFailure(status.Error(codes.Aborted, "incorrect timestamp")))
}

func TestIsMissingRecordCanonicalOnly(t *testing.T) {
	assert.True(t, IsMissingRecord(&PeerResponseError{Status: 500, Message: registry.ErrCodeMissingDependency}))
	assert.False(t, IsMissingRecord(&PeerResponseError{Status: 500, Message: "D0:MISSING_DEPENDENCY"}))
	assert.False(t, IsMissingRecord(&PeerResponseError{Status: 404, Message: registry.ErrCodeMissingDependency}))
	assert.False(t, IsMissingRecord(&PeerResponseError{Status: 500, Message: registry.ErrCodeUnauthorized}))
}

func TestPostLockProbePreservesOriginalDeadline(t *testing.T) {
	start := time.Now()
	now := start.Add(4 * time.Second)
	old := ProbeLease{
		TxID:           "old",
		SentAt:         start,
		Deadline:       start.Add(5 * time.Second),
		SentMonoNs:     1,
		DeadlineMonoNs: 5_000_000_001,
	}
	rt := &Online{
		ready:     true,
		TimeLimit: 5 * time.Second,
		attempts:  map[string]time.Time{"old": start},
	}
	sp := &StateProvider{
		runtime:   rt,
		monoClock: func() time.Time { return now },
		lastProbe: &old,
	}

	got, err := sp.IsProbeFresh(old)
	require.NoError(t, err)
	assert.Equal(t, old.TxID, got.TxID)
	assert.True(t, got.Deadline.Equal(old.Deadline))
	assert.Equal(t, old.DeadlineMonoNs, got.DeadlineMonoNs)

	// Adopting a newer probe must NOT extend the original request's deadline.
	newProbe := ProbeLease{TxID: "new", SentAt: now, Deadline: now.Add(5 * time.Second)}
	rt.attempts["new"] = now
	sp.lastProbe = &newProbe
	now = old.Deadline

	_, err = sp.IsProbeFresh(old)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateStale))

	gotNew, err := sp.IsProbeFresh()
	require.NoError(t, err)
	assert.Equal(t, "new", gotNew.TxID)

	rt.ready = false
	_, err = sp.IsProbeFresh(newProbe)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateUnavailable))
}
