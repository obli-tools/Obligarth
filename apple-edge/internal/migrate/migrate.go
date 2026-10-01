// Package migrate applies the embedded SQL migrations of apple-edge and
// checks, at start-up, that the database is exactly at the expected version.
//
// Upstream schemas (NanoMDM) ship a schema.sql, not migrations: the first
// migration of such a component is a verbatim copy of that file, and every
// later upstream change must be written by hand as an ALTER migration.
package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lib/pq"
)

//go:embed sql
var files embed.FS

// Components, in application order, with their schema.
var components = []struct{ Name, Schema string }{
	{"nanomdm", "nanomdm"},
	{"apple_edge", "apple_edge"},
}

// Roles created and used by the migrations.
const (
	RoleOwner        = "apple_edge_owner"
	RoleApp          = "apple_edge_app"
	RoleOutboxReader = "apple_edge_outbox_reader"
)

// Upstream schema versions absorbed by the migrations (drift guard).
const (
	NanoMDMSchemaSHA256 = "33480889eb1154d1213ebba7d99b39fe1f02533266a23733a9b0b2500aceed6b"
	NanoMDMSchemaFile   = "sql/nanomdm/0001_upstream_schema.sql"
)

// ExitCodeSchemaMismatch is the exit code of serve when the database is not
// at the version expected by the binary.
const ExitCodeSchemaMismatch = 3

// Migration is one embedded SQL file.
type Migration struct {
	Component string
	Schema    string
	Version   int
	Name      string
	SQL       string
	SHA256    string
}

var fileRe = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// All returns the embedded migrations in application order.
func All() ([]Migration, error) {
	var out []Migration
	for _, c := range components {
		entries, err := fs.ReadDir(files, path.Join("sql", c.Name))
		if err != nil {
			return nil, err
		}
		var ms []Migration
		for _, e := range entries {
			m := fileRe.FindStringSubmatch(e.Name())
			if m == nil {
				return nil, fmt.Errorf("migrate: unexpected file %s/%s", c.Name, e.Name())
			}
			b, err := files.ReadFile(path.Join("sql", c.Name, e.Name()))
			if err != nil {
				return nil, err
			}
			text := normalize(string(b))
			v, _ := strconv.Atoi(m[1])
			sum := sha256.Sum256([]byte(text))
			ms = append(ms, Migration{Component: c.Name, Schema: c.Schema, Version: v, Name: m[2], SQL: text, SHA256: hex.EncodeToString(sum[:])})
		}
		slices.SortFunc(ms, func(a, b Migration) int { return a.Version - b.Version })
		for i, m := range ms {
			if m.Version != i+1 {
				return nil, fmt.Errorf("migrate: %s versions must be contiguous from 1", c.Name)
			}
		}
		out = append(out, ms...)
	}
	return out, nil
}

// normalize makes the checksum independent of the checkout's line endings.
func normalize(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// EmbeddedFile returns the normalized content of an embedded file (tests).
func EmbeddedFile(name string) (string, error) {
	b, err := files.ReadFile(name)
	return normalize(string(b)), err
}

// UpOptions configures Up.
type UpOptions struct {
	// AppPassword is set on the apple_edge_app role.
	AppPassword string
	// OutboxReaderGrantee is the brain's role, granted apple_edge_outbox_reader ("" to skip).
	OutboxReaderGrantee string
	// Logf receives progress and warnings.
	Logf func(format string, args ...any)
}

const lockKey = "apple_edge.migrate"

// Up creates the roles and schemas, applies pending migrations and sets the
// privileges. It runs on an administration connection (superuser or a role
// with CREATEROLE) and is idempotent.
func Up(ctx context.Context, admin *sql.DB, o UpOptions) error {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.AppPassword == "" {
		return errors.New("migrate: empty password for " + RoleApp)
	}
	all, err := All()
	if err != nil {
		return err
	}
	conn, err := admin.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext($1))`, lockKey); err != nil {
		return fmt.Errorf("migrate: lock: %w", err)
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext($1))`, lockKey)

	if err := ensureRoles(ctx, conn, o); err != nil {
		return err
	}
	for _, c := range components {
		if _, err := conn.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+pq.QuoteIdentifier(c.Schema)+` AUTHORIZATION `+RoleOwner); err != nil {
			return fmt.Errorf("migrate: schema %s: %w", c.Schema, err)
		}
	}
	if err := bootstrap(ctx, conn); err != nil {
		return err
	}
	applied, err := readApplied(ctx, conn)
	if err != nil {
		return err
	}
	if err := compare(all, applied, true); err != nil {
		return err
	}
	for _, m := range all {
		if _, ok := applied[key(m.Component, m.Version)]; ok {
			continue
		}
		if err := apply(ctx, conn, m); err != nil {
			return err
		}
		o.Logf("applied migration %s %04d_%s", m.Component, m.Version, m.Name)
	}
	return grant(ctx, conn, o)
}

func ensureRoles(ctx context.Context, conn *sql.Conn, o UpOptions) error {
	for _, r := range []struct {
		name, attrs string
	}{
		{RoleOwner, "NOLOGIN"},
		{RoleApp, "LOGIN"},
		{RoleOutboxReader, "NOLOGIN"},
	} {
		var exists bool
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, r.name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			if _, err := conn.ExecContext(ctx, `CREATE ROLE `+r.name+` `+r.attrs); err != nil {
				return fmt.Errorf("migrate: create role %s: %w", r.name, err)
			}
		}
	}
	stmts := []string{
		`ALTER ROLE ` + RoleApp + ` WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD ` + pq.QuoteLiteral(o.AppPassword),
		`ALTER ROLE ` + RoleApp + ` SET statement_timeout = '15s'`,
		`ALTER ROLE ` + RoleApp + ` SET lock_timeout = '5s'`,
		`ALTER ROLE ` + RoleApp + ` SET idle_in_transaction_session_timeout = '30s'`,
		`ALTER ROLE ` + RoleApp + ` SET TimeZone = 'UTC'`,
	}
	for _, s := range stmts {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate: configure role %s: %w", RoleApp, err)
		}
	}
	// A non-superuser administrator must be able to SET ROLE to the owner.
	var super bool
	if err := conn.QueryRowContext(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&super); err != nil {
		return err
	}
	if !super {
		if _, err := conn.ExecContext(ctx, `GRANT `+RoleOwner+` TO CURRENT_USER`); err != nil {
			return fmt.Errorf("migrate: grant %s to the administrator: %w", RoleOwner, err)
		}
	}
	return nil
}

func bootstrap(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, `
SET ROLE `+RoleOwner+`;
CREATE TABLE IF NOT EXISTS apple_edge.schema_migrations (
    component   text        NOT NULL CHECK (component IN ('apple_edge', 'nanomdm', 'nanodep')),
    version     integer     NOT NULL,
    name        text        NOT NULL,
    sha256      char(64)    NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (component, version)
);
RESET ROLE;`)
	if err != nil {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `RESET ROLE`)
		return fmt.Errorf("migrate: bootstrap: %w", err)
	}
	return nil
}

type appliedRow struct {
	name, sha string
}

func key(component string, version int) string { return component + "/" + strconv.Itoa(version) }

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func readApplied(ctx context.Context, q querier) (map[string]appliedRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT component, version, name, sha256 FROM apple_edge.schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]appliedRow{}
	for rows.Next() {
		var c, n, s string
		var v int
		if err := rows.Scan(&c, &v, &n, &s); err != nil {
			return nil, err
		}
		out[key(c, v)] = appliedRow{name: n, sha: strings.TrimSpace(s)}
	}
	return out, rows.Err()
}

// compare checks the applied migrations against the embedded ones. With
// allowPending, embedded migrations not yet applied are accepted (migrate
// up); otherwise the sets must be identical (serve).
func compare(all []Migration, applied map[string]appliedRow, allowPending bool) error {
	known := map[string]bool{}
	var problems []string
	for _, m := range all {
		k := key(m.Component, m.Version)
		known[k] = true
		a, ok := applied[k]
		switch {
		case !ok && !allowPending:
			problems = append(problems, fmt.Sprintf("%s %04d not applied", m.Component, m.Version))
		case ok && a.sha != m.SHA256:
			problems = append(problems, fmt.Sprintf("%s %04d was modified after being applied", m.Component, m.Version))
		}
	}
	for k := range applied {
		if !known[k] {
			problems = append(problems, fmt.Sprintf("migration %s is unknown to this binary (newer database)", k))
		}
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return &MismatchError{Problems: problems}
	}
	return nil
}

// MismatchError reports a database that is not at the expected version.
type MismatchError struct{ Problems []string }

func (e *MismatchError) Error() string {
	return "migrate: schema mismatch: " + strings.Join(e.Problems, "; ")
}

func apply(ctx context.Context, conn *sql.Conn, m Migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmts := []string{
		`SET LOCAL ROLE ` + RoleOwner,
		`SET LOCAL search_path = ` + pq.QuoteIdentifier(m.Schema),
		m.SQL,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate: %s %04d_%s: %w", m.Component, m.Version, m.Name, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO apple_edge.schema_migrations (component, version, name, sha256) VALUES ($1, $2, $3, $4)`,
		m.Component, m.Version, m.Name, m.SHA256); err != nil {
		return fmt.Errorf("migrate: record %s %04d: %w", m.Component, m.Version, err)
	}
	return tx.Commit()
}

func grant(ctx context.Context, conn *sql.Conn, o UpOptions) error {
	schemas := make([]string, 0, len(components))
	for _, c := range components {
		schemas = append(schemas, pq.QuoteIdentifier(c.Schema))
	}
	list := strings.Join(schemas, ", ")
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmts := []string{
		`SET LOCAL ROLE ` + RoleOwner,
		`GRANT USAGE ON SCHEMA ` + list + ` TO ` + RoleApp,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ` + list + ` TO ` + RoleApp,
		`GRANT USAGE ON ALL SEQUENCES IN SCHEMA ` + list + ` TO ` + RoleApp,
		`REVOKE INSERT, UPDATE, DELETE ON apple_edge.schema_migrations FROM ` + RoleApp,
		`GRANT USAGE ON SCHEMA apple_edge TO ` + RoleOutboxReader,
		`GRANT SELECT, UPDATE (consumed_at) ON apple_edge.outbox TO ` + RoleOutboxReader,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate: grants: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if o.OutboxReaderGrantee == "" {
		o.Logf("no outbox reader grantee configured: %s is granted to nobody", RoleOutboxReader)
		return nil
	}
	var super, bypass bool
	err = conn.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1`, o.OutboxReaderGrantee).Scan(&super, &bypass)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("migrate: role %q (EDGE_OUTBOX_READER_GRANTEE) does not exist", o.OutboxReaderGrantee)
	}
	if err != nil {
		return err
	}
	if super || bypass {
		o.Logf("WARNING: role %q is a superuser or bypasses RLS: the database does not isolate apple-edge from the brain", o.OutboxReaderGrantee)
	}
	if _, err := conn.ExecContext(ctx, `GRANT `+RoleOutboxReader+` TO `+pq.QuoteIdentifier(o.OutboxReaderGrantee)); err != nil {
		return fmt.Errorf("migrate: grant %s: %w", RoleOutboxReader, err)
	}
	return nil
}

// Check verifies that the applied migrations are exactly the embedded ones.
// serve calls it at start-up with the application role.
func Check(ctx context.Context, db *sql.DB) error {
	all, err := All()
	if err != nil {
		return err
	}
	applied, err := readApplied(ctx, db)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && (pqErr.Code == "42P01" || pqErr.Code == "3F000") {
			return &MismatchError{Problems: []string{"no migration applied"}}
		}
		return err
	}
	return compare(all, applied, false)
}

// Status describes the applied migrations (internal API).
type Status struct {
	Component string `json:"component"`
	Version   int    `json:"version"`
}

// Expected returns the latest embedded version of each component.
func Expected() ([]Status, error) {
	all, err := All()
	if err != nil {
		return nil, err
	}
	latest := map[string]int{}
	for _, m := range all {
		latest[m.Component] = max(latest[m.Component], m.Version)
	}
	var out []Status
	for _, c := range components {
		out = append(out, Status{Component: c.Name, Version: latest[c.Name]})
	}
	return out, nil
}
