// Package store holds the PostgreSQL plumbing of apple-edge: connection
// pools, transactions, the key ring (KEK/DEK), device secrets, the
// registries of device identifiers and issued certificates, and the
// wrapper around NanoMDM's storage that keeps protocol secrets out of the
// upstream tables.
package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lib/pq"
)

// DSN returns a connection URL for rawURL (no password inside) with the
// password and the session parameters of apple-edge. searchPath may be empty.
func DSN(rawURL, password, searchPath string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		return "", errors.New("database URL must be of the form postgres://user@host:port/db")
	}
	if u.User == nil || u.User.Username() == "" {
		return "", errors.New("database URL must name the user")
	}
	if _, has := u.User.Password(); has {
		return "", errors.New("database URL must not contain a password (use the password file)")
	}
	if password != "" {
		u.User = url.UserPassword(u.User.Username(), password)
	}
	q := u.Query()
	if searchPath != "" {
		q.Set("search_path", searchPath)
	}
	q.Set("TimeZone", "UTC")
	if q.Get("application_name") == "" {
		q.Set("application_name", "apple-edge")
	}
	if q.Get("connect_timeout") == "" {
		q.Set("connect_timeout", "10")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// OpenPool opens a pool with the sizing rules of apple-edge.
func OpenPool(dsn string, maxConns int) (*sql.DB, error) {
	connector, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)
	return db, nil
}

// WaitReady pings db with exponential back-off until it answers or max elapses.
func WaitReady(ctx context.Context, db *sql.DB, max time.Duration, onRetry func(error)) error {
	deadline := time.Now().Add(max)
	delay := 250 * time.Millisecond
	for {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := db.PingContext(pctx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().Add(delay).After(deadline) {
			return fmt.Errorf("database not reachable: %w", err)
		}
		if onRetry != nil {
			onRetry(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 8*time.Second)
	}
}

// InTx runs fn in a transaction, committing if fn returns nil.
func InTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Querier is implemented by *sql.DB, *sql.Tx and *sql.Conn.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// PGCode returns the SQLSTATE of err and the constraint involved, if any.
func PGCode(err error) (code, constraint string) {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return string(pqErr.Code), pqErr.Constraint
	}
	return "", ""
}

// IsUniqueViolation reports a unique violation, optionally on a given constraint.
func IsUniqueViolation(err error, constraint string) bool {
	code, c := PGCode(err)
	return code == "23505" && (constraint == "" || c == constraint)
}

// IsCheckViolation reports a CHECK violation, optionally on a given constraint.
func IsCheckViolation(err error, constraint string) bool {
	code, c := PGCode(err)
	return code == "23514" && (constraint == "" || c == constraint)
}

// IsLockTimeout reports a lock_timeout or statement cancellation.
func IsLockTimeout(err error) bool {
	code, _ := PGCode(err)
	return code == "55P03" || code == "57014"
}

// IsUnavailable reports a transient failure of the database itself:
// connection refused or lost, too many connections, server shutting down
// or starting up. Callers answer "try again later".
func IsUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, driver.ErrBadConn) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	code, _ := PGCode(err)
	return strings.HasPrefix(code, "08") || strings.HasPrefix(code, "53") || code == "57P01" || code == "57P02" || code == "57P03"
}

// TryXactLock takes a transaction-scoped advisory lock for singleton jobs;
// it returns false when another replica holds it.
func TryXactLock(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtext($1))`, "apple_edge:"+name).Scan(&ok)
	return ok, err
}

// Notify sends a NOTIFY inside tx (delivered at commit).
func Notify(ctx context.Context, q Querier, channel, payload string) error {
	_, err := q.ExecContext(ctx, `SELECT pg_notify($1, $2)`, channel, payload)
	return err
}

// NamespacePrefix returns "<key>_", the prefix of a tenant's enrollment ids.
func NamespacePrefix(tenantKey string) string { return tenantKey + "_" }

// Truncate shortens s for storage in free-text columns.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
