package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	platformrt "grad/platform/bootstrap"
	"grad/platform/core/ledger"
	"grad/protocol"
	"grad/protocol/registry"
)

// deployment captures fields read from ledgerctl deploy JSON output.
type deployment struct {
	DeploymentID string             `json:"deploymentId"`
	Bootstrap    registry.Bootstrap `json:"bootstrap"`
	Raw          json.RawMessage    `json:"-"`
}

type seedReport struct {
	Operations []*ledger.Operation `json:"operations"`
}

func (e *e1Trial) command(ctx context.Context, output any, command string, extra ...string) error {
	args := append([]string{command, "--dir", e.instanceDir}, extra...)
	cmd := exec.CommandContext(ctx, e.ledgerctl, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if len(raw) != 0 && output != nil {
		if decodeErr := json.Unmarshal(raw, output); decodeErr != nil {
			return fmt.Errorf("ledgerctl %s malformed JSON: %w", command, decodeErr)
		}
	}
	if err != nil {
		return fmt.Errorf("ledgerctl %s: %w: %s", command, err, e.redact(strings.TrimSpace(stderr.String())))
	}
	if d, ok := output.(*deployment); ok {
		d.Raw = raw
	}
	return nil
}

func (e *e1Trial) prepareRegistry() error {
	fx, err := platformrt.PrepareFixtures(e.inst, e.dep, nil)
	if err != nil {
		return fmt.Errorf("prepare protocol fixtures: %w", err)
	}
	e.f = *fx

	pending := map[string]*ledger.Operation{}
	for _, pair := range []struct{ domain, role string }{{"A", "U"}, {"B", "B1"}, {"C", "C"}} {
		// Use the same operation key and bytes as seed so its normal retry resumes from this step.
		if _, err := e.invoke("seed/domain-"+pair.domain, "T", "BootstrapDomain", e.f.Domains[pair.domain], "VALID"); err != nil {
			return err
		}
		op, err := e.invoke(e.id+"/F01-pending-"+pair.domain, "registrar"+pair.domain, "RegisterIdentity", e.f.Identities[pair.role], registry.ErrCodeInvalidState)
		if err != nil {
			return err
		}
		pending[pair.domain] = op
	}
	if err := e.save("F01-pending", pending); err != nil {
		return err
	}
	var raw json.RawMessage
	runErr := e.command(e.ctx, &raw, "seed")
	if len(raw) != 0 {
		runErr = errors.Join(runErr, e.save("seed", raw), json.Unmarshal(raw, &e.seed))
	}
	e.seed.Operations = append(e.seed.Operations, pending["A"], pending["B"], pending["C"])
	return runErr
}

func (e *e1Trial) invoke(label, role, method string, input any, expected string) (*ledger.Operation, error) {
	file, err := os.CreateTemp(e.instanceDir, "e1-input-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	// ledgerctl hashes its compact argument, so use json.Marshal and retain the seed field order.
	data, err := json.Marshal(input)
	if err == nil {
		_, err = file.Write(data)
	}
	if err := errors.Join(err, file.Close()); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	runErr := e.command(e.ctx, &raw, "invoke", "--key", label, "--role", role, "--method", method, "--input", file.Name())
	if len(raw) == 0 {
		return nil, runErr
	}
	e.event("operation", raw)
	var op ledger.Operation
	if err := json.Unmarshal(raw, &op); err != nil {
		return nil, errors.Join(runErr, err)
	}
	if runErr != nil {
		return &op, runErr
	}
	if expected == "VALID" && op.Status == "CONFIRMED" && op.Commit != nil && op.Commit.Code == "VALID" {
		return &op, nil
	}
	if expected != "VALID" && op.Status == "FAILED" && op.FailureCode != nil && *op.FailureCode == expected {
		return &op, nil
	}
	return &op, fmt.Errorf("%s expected %s; observed %s at %s (%s)", label, expected, op.Status, op.Stage, op.Observation)
}

func (e *e1Trial) op(label, role, method string, input any, expected string) (*ledger.Operation, error) {
	return e.invoke(e.id+"/"+label, role, method, input, expected)
}

func (e *e1Trial) seedOperation(label string) *ledger.Operation {
	for _, op := range e.seed.Operations {
		if op != nil && op.Key == "seed/"+label {
			return op
		}
	}
	return nil
}

type checkResult struct {
	ledger.Point
	DeploymentID string                     `json:"deploymentId"`
	Probe        ledger.ProbeLease          `json:"probe"`
	Records      map[string]json.RawMessage `json:"records"`
}

type liveState struct {
	ledger.StateSource
	trial *e1Trial
}

func (s *liveState) AssembleSnapshot(ctx context.Context, leaf string, now time.Time) (*ledger.StateSnapshot, error) {
	if _, err := s.trial.refresh(ctx, leaf); err != nil {
		return nil, err
	}
	return s.StateSource.AssembleSnapshot(ctx, leaf, now)
}

func (e *e1Trial) refresh(ctx context.Context, leaf string) (checkResult, error) {
	if leaf == "" {
		leaf = e.f.RPG2.ID
	}
	send := time.Now()
	var check checkResult
	if err := e.command(ctx, &check, "check", "--grant", leaf, "--timeout", "18s"); err != nil {
		e.event("probe_failed", e.redact(err.Error()))
		return check, protocol.WrapError(protocol.ErrCodeStateUnavailable, "ledgerctl check", err)
	}
	received := time.Now()
	p := check.Probe
	duration := p.Deadline.Sub(p.SentAt)
	if check.DeploymentID != e.d.DeploymentID || p.TxID == "" || p.ProbeBlock > check.Number ||
		p.SentAt.Before(send) || p.SentAt.After(received) || duration != registry.ProbeLifetime ||
		p.DeadlineMonoNs-p.SentMonoNs != duration.Nanoseconds() || !received.Before(p.Deadline) {
		return check, protocol.NewError(protocol.ErrCodeStateStale, "expired or foreign ledgerctl probe")
	}
	// Re-anchor wall timestamps to the driver's local monotonic clock on the same host.
	// The probe ID, relative monotonic budget and original expiry come from the subprocess.
	p.SentAt = received.Add(p.SentAt.Sub(received))
	p.Deadline = p.SentAt.Add(duration)
	e.sp.SetStaticProbe(&p)
	e.event("probe", map[string]any{"case": e.stage, "deploymentId": check.DeploymentID, "checkpoint": check.Point, "probe": p})
	return check, nil
}

func (e *e1Trial) currentView(ctx context.Context, leaf string) (*ledger.ConsistentProtocolView, error) {
	if _, err := e.refresh(ctx, leaf); err != nil {
		return nil, err
	}
	return e.sp.AssembleProtocolSnapshot(ctx, leaf, time.Now())
}

func (e *e1Trial) waitApplied(block uint64) error {
	check, err := e.refresh(e.ctx, e.f.RPG2.ID)
	if err != nil {
		return err
	}
	if check.Number < block {
		return fmt.Errorf("block %d has not been applied; current %d", block, check.Number)
	}
	return nil
}

func (e *e1Trial) rawAt(kind, id string, block uint64) ([]byte, error) {
	var raw []byte
	err := e.db.QueryRow(e.ctx, `SELECT value FROM fabric_version WHERE deployment=$1 AND key=$2 AND block_no<=$3 ORDER BY block_no DESC,tx_index DESC LIMIT 1`,
		e.d.DeploymentID, registry.Key(kind, id), block).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

func currentRecord[T any](e *e1Trial, kind, id string) (T, error) {
	var value T
	var raw []byte
	if err := e.db.QueryRow(e.ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`, e.d.DeploymentID, registry.Key(kind, id)).Scan(&raw); err != nil {
		return value, err
	}
	return value, json.Unmarshal(raw, &value)
}

func (e *e1Trial) absent(kind, id string) error {
	if _, err := currentRecord[json.RawMessage](e, kind, id); errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return fmt.Errorf("expected %s/%s absent from the Fabric view", kind, id)
}

func decodeGrantPayload(jws string) (protocol.GrantClaims, error) {
	var claims protocol.GrantClaims
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return claims, fmt.Errorf("invalid compact grant JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, err
	}
	return claims, protocol.DecodeStrictJSON(raw, &claims)
}

func derefStr(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
