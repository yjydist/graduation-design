// Package central implements a registry state source backed by the business primary database.
package central

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/migrations"
	"grad/platform/state"
	"grad/protocol"
	"grad/protocol/registry"
)

var _ state.StateSource = (*Source)(nil)

// Source serves consistent registry snapshots directly from PostgreSQL without
// querying Fabric state or fabricating a probe lease.
type Source struct {
	DB           *pgxpool.Pool
	DeploymentID string
	Root         registry.RootRecord
	// AfterRead is an optional deterministic concurrency test hook inside the read transaction.
	AfterRead func()
}

type registryRow struct {
	Revision int64     `db:"revision"`
	ReadAt   time.Time `db:"read_at"`
	Snapshot []byte    `db:"snapshot"`
}

// EnsureSchema applies embedded PostgreSQL migrations required by the centralized registry.
func EnsureSchema(ctx context.Context, db *pgxpool.Pool) error {
	return migrations.Up(ctx, db)
}

// Initialize atomically installs the shared trusted registration input at revision 1.
func Initialize(ctx context.Context, db *pgxpool.Pool, snap *protocol.SnapshotView) (*Source, error) {
	if snap == nil || snap.DeploymentID == "" {
		return nil, fmt.Errorf("central registration input required")
	}
	if err := EnsureSchema(ctx, db); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, `INSERT INTO centralized_registry(deployment_id, revision, snapshot) VALUES($1, 1, $2)`, snap.DeploymentID, raw); err != nil {
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
	if err := tx.QueryRow(ctx, `SELECT revision, snapshot FROM centralized_registry WHERE deployment_id=$1 FOR UPDATE`, s.DeploymentID).Scan(&revision, &raw); err != nil {
		return err
	}
	if revision != expected {
		return protocol.NewError(protocol.ErrCodeStateChanged, "central registry revision changed")
	}
	var snap protocol.SnapshotView
	if err := json.Unmarshal(raw, &snap); err != nil {
		return err
	}
	if err := change(&snap); err != nil {
		return err
	}
	if snap.Root != s.Root || snap.DeploymentID != s.DeploymentID {
		return fmt.Errorf("central registry deployment/root cannot change")
	}
	raw, err = json.Marshal(&snap)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE centralized_registry SET revision=revision+1, snapshot=$2 WHERE deployment_id=$1`, s.DeploymentID, raw); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AssembleSnapshot reads the centralized registry in a REPEATABLE READ transaction
// and narrows the returned SnapshotView to the leaf grant's dependency closure.
func (s *Source) AssembleSnapshot(ctx context.Context, leafGrantID string, now time.Time) (*state.StateSnapshot, error) {
	view, err := s.ReadRegistry(ctx)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	view.Snapshot.Now = now.UTC()
	view.Snapshot.Height = 0
	view.Snapshot.ExactIntervalBounds = true
	view.Snapshot.ClockError = registry.ClockError
	if err := dependencies(view.Snapshot, leafGrantID); err != nil {
		return nil, unavailable(err)
	}
	return view, nil
}

// ReadRegistry reads all persisted anchors and their revision checkpoint in one REPEATABLE READ snapshot.
func (s *Source) ReadRegistry(ctx context.Context) (*state.StateSnapshot, error) {
	if s == nil || s.DB == nil {
		return nil, unavailable(fmt.Errorf("central registry database is nil"))
	}
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, unavailable(err)
	}
	defer tx.Rollback(context.Background())

	rows, err := tx.Query(ctx, `SELECT revision, clock_timestamp() AS read_at, snapshot FROM centralized_registry WHERE deployment_id=$1`, s.DeploymentID)
	if err != nil {
		return nil, unavailable(err)
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[registryRow])
	if err != nil {
		return nil, unavailable(err)
	}
	if s.AfterRead != nil {
		s.AfterRead()
	}
	var snap protocol.SnapshotView
	if err := json.Unmarshal(row.Snapshot, &snap); err != nil {
		return nil, unavailable(err)
	}
	if snap.DeploymentID != s.DeploymentID || snap.Root != s.Root {
		return nil, unavailable(fmt.Errorf("central deployment/root mismatch"))
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, unavailable(err)
	}
	return &state.StateSnapshot{
		DeploymentID: s.DeploymentID,
		StateSource:  state.SourceCentralized,
		Revision:     row.Revision,
		StateReadAt:  row.ReadAt.UTC(),
		Snapshot:     &snap,
	}, nil
}

// LockCheckpoint acquires a FOR SHARE lock on the centralized registry row inside tx
// and reports whether the committed revision still matches original.
func (s *Source) LockCheckpoint(ctx context.Context, tx pgx.Tx, original *state.StateSnapshot) (bool, error) {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM centralized_registry WHERE deployment_id=$1 FOR SHARE`, s.DeploymentID).Scan(&revision); err != nil {
		return false, unavailable(err)
	}
	return original != nil && original.StateSource == state.SourceCentralized && original.Revision == revision, nil
}

// CheckFresh validates that original carries centralized snapshot metadata.
// Centralized mode has no Fabric probe lease; freshness is enforced via revision locks.
func (s *Source) CheckFresh(ctx context.Context, original *state.StateSnapshot) (state.ProbeLease, error) {
	if original == nil || original.StateSource != state.SourceCentralized || original.Revision < 1 || original.StateReadAt.IsZero() {
		return state.ProbeLease{}, unavailable(fmt.Errorf("central snapshot metadata missing"))
	}
	return state.ProbeLease{}, nil
}

func unavailable(err error) error {
	return protocol.WrapError(protocol.ErrCodeStateUnavailable, "central registry read/lock failed", err)
}

func dependencies(s *protocol.SnapshotView, leaf string) error {
	// Return the same dependency closure as the Fabric path. Unrelated domains must not add delivery prerequisites.
	out := *s
	out.Domains = map[string]registry.Domain{}
	out.Certifications = map[string]registry.Certification{}
	out.Identities = map[string]registry.Identity{}
	out.Credentials = map[string]registry.Credential{}
	out.Tasks = map[string]registry.Task{}
	out.Grants = map[string]registry.Grant{}

	missing := func(kind, id string) error { return fmt.Errorf("%s: %s/%s", registry.ErrCodeMissingDependency, kind, id) }
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
			cert, ok := s.Certifications[d.Certification]
			if !ok {
				return missing("certification", d.Certification)
			}
			out.Domains[d.ID] = d
			out.Certifications[d.Certification] = cert
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
