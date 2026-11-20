// Package centralstate implements a registry backed by the business primary database.
package centralstate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
)

const schema = `CREATE TABLE IF NOT EXISTS centralized_registry (
 deployment_id text PRIMARY KEY,
 revision bigint NOT NULL CHECK(revision > 0),
 snapshot jsonb NOT NULL
);`

// Source never queries Fabric state or supplies a simulated probe.
type Source struct {
	DB           *pgxpool.Pool
	DeploymentID string
	Root         api.RootRecord
	// AfterRead is an optional deterministic concurrency test hook inside the read transaction.
	AfterRead func()
}

// Initialize atomically installs the shared trusted registration input at revision 1.
// The caller explicitly selects an independent, empty database.
func Initialize(ctx context.Context, db *pgxpool.Pool, snap *protocol.SnapshotView) (*Source, error) {
	if snap == nil || snap.DeploymentID == "" {
		return nil, fmt.Errorf("central registration input required")
	}
	if _, err := db.Exec(ctx, schema); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec(ctx, `INSERT INTO centralized_registry(deployment_id,revision,snapshot) VALUES($1,1,$2)`, snap.DeploymentID, raw); err != nil {
		return nil, err
	}
	return &Source{DB: db, DeploymentID: snap.DeploymentID, Root: snap.Root}, nil
}

// Update serializes writers on the version row and commits all records with their new revision.
func (s *Source) Update(ctx context.Context, expected int64, change func(*protocol.SnapshotView) error) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	var revision int64
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT revision,snapshot FROM centralized_registry WHERE deployment_id=$1 FOR UPDATE`, s.DeploymentID).Scan(&revision, &raw); err != nil {
		return err
	}
	if revision != expected {
		return protocol.NewError(protocol.ErrCodeStateChanged, "central registry revision changed")
	}
	var snap protocol.SnapshotView
	if err = json.Unmarshal(raw, &snap); err != nil {
		return err
	}
	if err = change(&snap); err != nil {
		return err
	}
	if snap.Root != s.Root || snap.DeploymentID != s.DeploymentID {
		return fmt.Errorf("central registry deployment/root cannot change")
	}
	raw, err = json.Marshal(&snap)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE centralized_registry SET revision=revision+1,snapshot=$2 WHERE deployment_id=$1`, s.DeploymentID, raw); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Source) AssembleSnapshot(ctx context.Context, leaf string, now time.Time) (*gateway.ConsistentSnapshot, error) {
	view, err := s.ReadRegistry(ctx)
	if err != nil {
		return nil, err
	}
	view.Snapshot.Now = now.UTC()
	view.Snapshot.Height = 0
	view.Snapshot.ExactIntervalBounds = true
	view.Snapshot.ClockError = api.ClockError
	if err := dependencies(view.Snapshot, leaf); err != nil {
		return nil, unavailable(err)
	}
	return view, nil
}

// ReadRegistry reads all persisted anchors and their checkpoint in one snapshot.
func (s *Source) ReadRegistry(ctx context.Context) (*gateway.ConsistentSnapshot, error) {
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, unavailable(err)
	}
	defer tx.Rollback(context.Background())
	var revision int64
	var at time.Time
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT revision,clock_timestamp(),snapshot FROM centralized_registry WHERE deployment_id=$1`, s.DeploymentID).Scan(&revision, &at, &raw); err != nil {
		return nil, unavailable(err)
	}
	if s.AfterRead != nil {
		s.AfterRead()
	}
	var snap protocol.SnapshotView
	if err = json.Unmarshal(raw, &snap); err != nil {
		return nil, unavailable(err)
	}
	if snap.DeploymentID != s.DeploymentID || snap.Root != s.Root {
		return nil, unavailable(fmt.Errorf("central deployment/root mismatch"))
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, unavailable(err)
	}
	return &gateway.ConsistentSnapshot{DeploymentID: s.DeploymentID, StateSource: gateway.StateCentralized, Revision: revision, StateReadAt: at.UTC(), Snapshot: &snap}, nil
}

func (s *Source) LockCheckpoint(ctx context.Context, tx pgx.Tx, original *gateway.ConsistentSnapshot) (bool, error) {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM centralized_registry WHERE deployment_id=$1 FOR SHARE`, s.DeploymentID).Scan(&revision); err != nil {
		return false, unavailable(err)
	}
	return original != nil && original.StateSource == gateway.StateCentralized && original.Revision == revision, nil
}

func (s *Source) CheckFresh(ctx context.Context, original *gateway.ConsistentSnapshot) (gateway.ProbeInfo, error) {
	if original == nil || original.StateSource != gateway.StateCentralized || original.Revision < 1 || original.StateReadAt.IsZero() {
		return gateway.ProbeInfo{}, unavailable(fmt.Errorf("central snapshot metadata missing"))
	}
	// Availability and revision are established by the actual read and lock. Business deadlines use the common gateway clock.
	return gateway.ProbeInfo{}, nil
}

func unavailable(err error) error {
	return protocol.WrapError(protocol.ErrCodeStateUnavailable, "central registry read/lock failed", err)
}

func dependencies(s *protocol.SnapshotView, leaf string) error {
	// Return the same dependency closure as the Fabric path. Unrelated domains must not add delivery prerequisites.
	out := *s
	out.Domains = map[string]api.Domain{}
	out.Certifications = map[string]api.Certification{}
	out.Identities = map[string]api.Identity{}
	out.Credentials = map[string]api.Credential{}
	out.Tasks = map[string]api.Task{}
	out.Grants = map[string]api.Grant{}
	missing := func(kind, id string) error { return fmt.Errorf("MISSING_DEPENDENCY: %s/%s", kind, id) }
	identity := func(id string) error {
		x, ok := s.Identities[id]
		if !ok {
			return missing("identity", id)
		}
		d, ok := s.Domains[x.Domain]
		if !ok {
			return missing("domain", x.Domain)
		}
		cert, ok := s.Certifications[d.Certification]
		if !ok {
			return missing("certification", d.Certification)
		}
		did, ok := s.Identities[d.DID]
		if !ok {
			return missing("identity", d.DID)
		}
		out.Identities[x.ID] = x
		out.Identities[did.ID] = did
		out.Domains[d.ID] = d
		out.Certifications[cert.ID] = cert
		return nil
	}
	credential := func(id string) error {
		x, ok := s.Credentials[id]
		if !ok {
			return missing("credential", id)
		}
		out.Credentials[x.ID] = x
		if err := identity(x.Issuer); err != nil {
			return err
		}
		return identity(x.Subject)
	}
	if leaf == "" {
		for _, id := range []string{"A", "C"} {
			d, ok := s.Domains[id]
			if !ok {
				return missing("domain", id)
			}
			if _, ok = s.Certifications[d.Certification]; !ok {
				return missing("certification", d.Certification)
			}
			out.Domains[d.ID] = d
			out.Certifications[d.Certification] = s.Certifications[d.Certification]
		}
		*s = out
		return nil
	}
	seen := map[string]bool{}
	for id := leaf; id != ""; {
		if seen[id] || len(seen) > 64 {
			return fmt.Errorf("invalid central grant path")
		}
		seen[id] = true
		g, ok := s.Grants[id]
		if !ok {
			return missing("grant", id)
		}
		t, ok := s.Tasks[g.Task]
		if !ok {
			return missing("task", g.Task)
		}
		out.Grants[g.ID] = g
		out.Tasks[t.ID] = t
		for _, cred := range []string{g.IssuerCredential, g.GranteeCredential, t.CreatorCredential} {
			if err := credential(cred); err != nil {
				return err
			}
		}
		for _, subject := range []string{g.Issuer, g.Grantee, t.Creator} {
			if err := identity(subject); err != nil {
				return err
			}
		}
		id = g.Parent
	}
	*s = out
	return nil
}
