// Package queue is the business view of the NanoMDM command queue:
// idempotent enqueueing restricted to the tenant's enrollments, secrets
// injected at delivery (placeholders), cancellation, expiry and retention.
package queue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/mdm"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store/nanomdmsql"
)

// Limits.
const (
	MaxCommandBytes = 4 << 20
	MaxTargets      = 10000
)

// Secret placeholders written by the brain and replaced at delivery.
const (
	placeholderPrefix  = "obligarth-secret:"
	UnlockPlaceholder  = placeholderPrefix + store.SecretUnlockToken
	unlockPlaceholderX = `<string>` + UnlockPlaceholder + `</string>`
)

var unlockKeyRe = regexp.MustCompile(`<key>UnlockToken</key>\s*<string>obligarth-secret:unlock_token</string>`)

// Push outcomes (step 1: always disabled).
const PushDisabled = "disabled"

// Upstream is the part of NanoMDM's storage the queue uses.
type Upstream interface {
	EnqueueCommand(ctx context.Context, id []string, cmd *mdm.Command) (map[string]error, error)
}

// Queue implements the command operations of the internal API.
type Queue struct {
	DB       *sql.DB
	Upstream Upstream
	Secrets  *store.Secrets
	Out      *outbox.Writer
	Logger   *obs.Logger
}

// EnqueueRequest is the body of POST .../commands.
type EnqueueRequest struct {
	CommandUUID     string     `json:"command_uuid"`
	CommandPlistB64 string     `json:"command_plist_b64"`
	Targets         []string   `json:"targets"`
	Push            bool       `json:"push"`
	ExpiresAt       *time.Time `json:"expires_at"`
}

// TargetResult is the per-target outcome of an enqueue.
type TargetResult struct {
	Queued bool   `json:"queued"`
	Push   string `json:"push"`
}

// EnqueueResponse is the answer of POST .../commands.
type EnqueueResponse struct {
	CommandUUID string                  `json:"command_uuid"`
	RequestType string                  `json:"request_type"`
	Targets     map[string]TargetResult `json:"targets"`
}

type checked struct {
	cmd          *mdm.Command
	bodySHA      string
	targetsSHA   string
	targets      []string
	secretKind   string
	expiresAt    *time.Time
	requestType  string
	commandUUID  string
	responseBody EnqueueResponse
}

// Enqueue queues a command for enrollments of tenant. created is false for
// an idempotent replay (same UUID, same plist, same targets).
func (q *Queue) Enqueue(ctx context.Context, tenant string, plistBytes []byte, req EnqueueRequest) (EnqueueResponse, bool, error) {
	c, err := q.check(tenant, plistBytes, req)
	if err != nil {
		return EnqueueResponse{}, false, err
	}
	if err := q.tenantAccepts(ctx, tenant); err != nil {
		return EnqueueResponse{}, false, err
	}
	if same, err := q.compareExisting(ctx, tenant, c); err != nil || same {
		return c.responseBody, false, err
	}
	if err := q.checkTargets(ctx, tenant, c); err != nil {
		return EnqueueResponse{}, false, err
	}
	if _, err := q.Upstream.EnqueueCommand(ctx, c.targets, c.cmd); err != nil {
		if !store.IsUniqueViolation(err, "") {
			return EnqueueResponse{}, false, err
		}
		// The UUID exists upstream: a concurrent replay, or an earlier
		// enqueue whose business rows were not written.
		if same, err := q.compareExisting(ctx, tenant, c); err != nil || same {
			return c.responseBody, false, err
		}
		var upstreamBody string
		if err := q.DB.QueryRowContext(ctx, `SELECT command FROM nanomdm.commands WHERE command_uuid = $1`, c.commandUUID).Scan(&upstreamBody); err != nil {
			return EnqueueResponse{}, false, apierr.Conflict("command_uuid_conflict", "command UUID already used")
		}
		if sum := sha256.Sum256([]byte(upstreamBody)); hex.EncodeToString(sum[:]) != c.bodySHA {
			return EnqueueResponse{}, false, apierr.Conflict("command_uuid_conflict", "command UUID already used")
		}
	}
	err = store.InTx(ctx, q.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.commands (command_uuid, tenant_key, request_type, body_sha256, targets_sha256, secret_kind, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (command_uuid) DO NOTHING`,
			c.commandUUID, tenant, c.requestType, c.bodySHA, c.targetsSHA, nullIf(c.secretKind), c.expiresAt)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errAlreadyRecorded
		}
		for _, t := range c.targets {
			if _, err := tx.ExecContext(ctx, `INSERT INTO apple_edge.command_targets (command_uuid, enrollment_id) VALUES ($1, $2)`, c.commandUUID, t); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, errAlreadyRecorded) {
		same, err := q.compareExisting(ctx, tenant, c)
		if err == nil && !same {
			err = apierr.Conflict("command_uuid_conflict", "command UUID already used")
		}
		return c.responseBody, false, err
	}
	if err != nil {
		return EnqueueResponse{}, false, err
	}
	return c.responseBody, true, nil
}

var errAlreadyRecorded = errors.New("queue: command already recorded")

func (q *Queue) check(tenant string, plistBytes []byte, req EnqueueRequest) (*checked, error) {
	if !ids.ValidUUID(req.CommandUUID) {
		return nil, apierr.BadRequest("command_uuid must be a UUID")
	}
	if len(plistBytes) == 0 || len(plistBytes) > MaxCommandBytes {
		return nil, apierr.New(413, "payload_too_large", "the command plist must hold 1 byte to 4 MiB")
	}
	if !bytes.HasPrefix(plistBytes, []byte("<?xml")) {
		return nil, apierr.Unprocessable("validation_failed", "the command must be an XML plist starting with <?xml")
	}
	cmd, err := mdm.DecodeCommand(plistBytes)
	if err != nil {
		return nil, apierr.Unprocessable("validation_failed", "command_plist_b64 is not a valid MDM command")
	}
	if cmd.CommandUUID != req.CommandUUID {
		return nil, apierr.Unprocessable("validation_failed", "the plist CommandUUID differs from command_uuid")
	}
	if len(req.Targets) == 0 || len(req.Targets) > MaxTargets {
		return nil, apierr.BadRequest("targets must hold 1 to 10000 enrollment ids")
	}
	targets := slices.Clone(req.Targets)
	slices.Sort(targets)
	targets = slices.Compact(targets)
	for _, t := range targets {
		if !ids.BelongsTo(tenant, t) {
			return nil, apierr.Unprocessable("target_outside_tenant", "every target must be an enrollment of this tenant")
		}
	}
	c := &checked{cmd: cmd, targets: targets, requestType: cmd.Command.RequestType, commandUUID: req.CommandUUID}
	if bytes.Contains(plistBytes, []byte(placeholderPrefix)) {
		if cmd.Command.RequestType != "ClearPasscode" || len(targets) != 1 ||
			bytes.Count(plistBytes, []byte(placeholderPrefix)) != 1 || !unlockKeyRe.Match(plistBytes) {
			return nil, apierr.Unprocessable("validation_failed", "secret placeholders are allowed once, for the UnlockToken of a single-target ClearPasscode")
		}
		c.secretKind = store.SecretUnlockToken
	}
	if req.ExpiresAt != nil {
		if !req.ExpiresAt.After(time.Now()) {
			return nil, apierr.BadRequest("expires_at must be in the future")
		}
		e := req.ExpiresAt.UTC()
		c.expiresAt = &e
	}
	body := sha256.Sum256(plistBytes)
	c.bodySHA = hex.EncodeToString(body[:])
	ts := sha256.Sum256([]byte(strings.Join(targets, "\n")))
	c.targetsSHA = hex.EncodeToString(ts[:])
	c.responseBody = EnqueueResponse{CommandUUID: c.commandUUID, RequestType: c.requestType, Targets: map[string]TargetResult{}}
	for _, t := range targets {
		c.responseBody.Targets[t] = TargetResult{Queued: true, Push: PushDisabled}
	}
	return c, nil
}

func (q *Queue) tenantAccepts(ctx context.Context, tenant string) error {
	var state string
	var frozen bool
	err := q.DB.QueryRowContext(ctx, `SELECT state, commands_frozen FROM apple_edge.tenants WHERE key = $1`, tenant).Scan(&state, &frozen)
	if errors.Is(err, sql.ErrNoRows) {
		return apierr.TenantNotFound
	}
	if err != nil {
		return err
	}
	if state != "active" && state != "suspended" {
		return apierr.Conflict("tenant_not_live", "the tenant is retiring or retired")
	}
	if frozen {
		return apierr.New(423, "commands_frozen", "commands are frozen for this tenant")
	}
	return nil
}

// compareExisting reports whether the command is already recorded with the
// same content; it returns a conflict error if the UUID is used differently.
func (q *Queue) compareExisting(ctx context.Context, tenant string, c *checked) (bool, error) {
	var owner, body, targets string
	err := q.DB.QueryRowContext(ctx, `SELECT tenant_key, body_sha256, targets_sha256 FROM apple_edge.commands WHERE command_uuid = $1`, c.commandUUID).Scan(&owner, &body, &targets)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if owner != tenant || body != c.bodySHA || targets != c.targetsSHA {
		return false, apierr.Conflict("command_uuid_conflict", "command UUID already used")
	}
	return true, nil
}

func (q *Queue) checkTargets(ctx context.Context, tenant string, c *checked) error {
	enabled, err := nanomdmsql.EnabledEnrollments(ctx, q.DB, c.targets)
	if err != nil {
		return err
	}
	for _, t := range c.targets {
		if !enabled[t] {
			return apierr.Unprocessable("target_outside_tenant", "every target must be an enabled enrollment of this tenant")
		}
	}
	if c.secretKind != "" {
		ok, err := q.Secrets.Has(ctx, tenant, c.targets[0], c.secretKind)
		if err != nil {
			return err
		}
		if !ok {
			return apierr.Unprocessable("secret_unavailable", "the device has not provided the secret")
		}
	}
	return nil
}

// Cancel stops the delivery of a command to some (or all) of its targets.
func (q *Queue) Cancel(ctx context.Context, tenant, commandUUID string, targets []string) (map[string]string, error) {
	out := map[string]string{}
	err := store.InTx(ctx, q.DB, func(tx *sql.Tx) error {
		var owner string
		err := tx.QueryRowContext(ctx, `SELECT tenant_key FROM apple_edge.commands WHERE command_uuid = $1`, commandUUID).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && owner != tenant) {
			return apierr.NotFound("command_not_found", "command not found")
		}
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
SELECT enrollment_id, delivered_at IS NOT NULL, completed_at IS NOT NULL, cancelled_at IS NOT NULL, expired_at IS NOT NULL
  FROM apple_edge.command_targets WHERE command_uuid = $1 FOR UPDATE`, commandUUID)
		if err != nil {
			return err
		}
		type st struct{ delivered, completed, cancelled, expired bool }
		all := map[string]st{}
		for rows.Next() {
			var id string
			var s st
			if err := rows.Scan(&id, &s.delivered, &s.completed, &s.cancelled, &s.expired); err != nil {
				rows.Close()
				return err
			}
			all[id] = s
		}
		rows.Close()
		if len(targets) == 0 {
			for id := range all {
				targets = append(targets, id)
			}
		}
		for _, t := range targets {
			if _, ok := all[t]; !ok {
				return apierr.Unprocessable("target_outside_tenant", "a target is not a target of this command")
			}
		}
		for _, t := range targets {
			s := all[t]
			switch {
			case s.completed:
				out[t] = "completed"
			case s.cancelled:
				out[t] = "cancelled"
			case s.expired:
				out[t] = "expired"
			default:
				if _, err := nanomdmsql.DeactivateQueueItem(ctx, tx, t, commandUUID); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.command_targets SET cancelled_at = now() WHERE command_uuid = $1 AND enrollment_id = $2`, commandUUID, t); err != nil {
					return err
				}
				if s.delivered {
					out[t] = "already_delivered"
				} else {
					out[t] = "cancelled"
				}
			}
		}
		return nil
	})
	return out, err
}

// ExpireDue deactivates the queue items of expired commands and emits
// mdm.command_expired. Singleton job, run every minute.
func (q *Queue) ExpireDue(ctx context.Context) (int, error) {
	n := 0
	err := store.InTx(ctx, q.DB, func(tx *sql.Tx) error {
		ok, err := store.TryXactLock(ctx, tx, "command-expiry")
		if err != nil || !ok {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
SELECT t.command_uuid, t.enrollment_id, c.tenant_key
  FROM apple_edge.command_targets t JOIN apple_edge.commands c USING (command_uuid)
 WHERE c.expires_at IS NOT NULL AND c.expires_at <= now()
   AND t.completed_at IS NULL AND t.cancelled_at IS NULL AND t.expired_at IS NULL
 ORDER BY t.command_uuid
 LIMIT 5000
   FOR UPDATE OF t SKIP LOCKED`)
		if err != nil {
			return err
		}
		type item struct{ uuid, id, tenant string }
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.uuid, &it.id, &it.tenant); err != nil {
				rows.Close()
				return err
			}
			items = append(items, it)
		}
		rows.Close()
		byCmd := map[string][]string{}
		tenantOf := map[string]string{}
		var order []string
		for _, it := range items {
			if _, err := nanomdmsql.DeactivateQueueItem(ctx, tx, it.id, it.uuid); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.command_targets SET expired_at = now() WHERE command_uuid = $1 AND enrollment_id = $2`, it.uuid, it.id); err != nil {
				return err
			}
			if _, seen := byCmd[it.uuid]; !seen {
				order = append(order, it.uuid)
			}
			byCmd[it.uuid] = append(byCmd[it.uuid], it.id)
			tenantOf[it.uuid] = it.tenant
		}
		for _, uuid := range order {
			if err := q.Out.Insert(ctx, tx, outbox.T(tenantOf[uuid], "mdm.command_expired", map[string]any{"targets": byCmd[uuid]}).WithCommand(uuid)); err != nil {
				return err
			}
		}
		n = len(items)
		return nil
	})
	if err == nil && n > 0 {
		q.Out.Committed()
	}
	return n, err
}

// PurgeClosed removes commands closed for more than retention, their
// inactive upstream queue items and orphan upstream commands.
func (q *Queue) PurgeClosed(ctx context.Context, retention time.Duration) (int, error) {
	n := 0
	err := store.InTx(ctx, q.DB, func(tx *sql.Tx) error {
		ok, err := store.TryXactLock(ctx, tx, "command-retention")
		if err != nil || !ok {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
DELETE FROM apple_edge.commands c
 WHERE c.created_at < now() - make_interval(secs => $1)
   AND NOT EXISTS (SELECT 1 FROM apple_edge.command_targets t WHERE t.command_uuid = c.command_uuid
                    AND t.completed_at IS NULL AND t.cancelled_at IS NULL AND t.expired_at IS NULL)
RETURNING c.command_uuid`, retention.Seconds())
		if err != nil {
			return err
		}
		var uuids []string
		for rows.Next() {
			var u string
			if err := rows.Scan(&u); err != nil {
				rows.Close()
				return err
			}
			uuids = append(uuids, u)
		}
		rows.Close()
		if len(uuids) == 0 {
			return nil
		}
		n = len(uuids)
		if err := nanomdmsql.DeleteInactiveQueueItems(ctx, tx, uuids); err != nil {
			return err
		}
		return nanomdmsql.DeleteOrphanCommands(ctx, tx, uuids)
	})
	return n, err
}

// CommandInfo is the business data of a command needed at delivery.
type CommandInfo struct {
	Tenant      string
	RequestType string
	SecretKind  string
}

// Info returns the business data of a command (found=false if unknown).
func Info(ctx context.Context, q store.Querier, commandUUID string) (CommandInfo, bool, error) {
	var ci CommandInfo
	var sk sql.NullString
	err := q.QueryRowContext(ctx, `SELECT tenant_key, request_type, secret_kind FROM apple_edge.commands WHERE command_uuid = $1`, commandUUID).Scan(&ci.Tenant, &ci.RequestType, &sk)
	if errors.Is(err, sql.ErrNoRows) {
		return ci, false, nil
	}
	ci.SecretKind = sk.String
	return ci, err == nil, err
}

// InjectSecret replaces the UnlockToken placeholder of a command plist by
// the secret, encoded as <data>.
func InjectSecret(raw []byte, secret []byte) ([]byte, bool) {
	if bytes.Count(raw, []byte(unlockPlaceholderX)) != 1 {
		return raw, false
	}
	data := []byte("<data>" + b64(secret) + "</data>")
	return bytes.Replace(raw, []byte(unlockPlaceholderX), data, 1), true
}

// MarkDelivered records the delivery of a command to an enrollment.
func MarkDelivered(ctx context.Context, q store.Querier, commandUUID, enrollmentID string) error {
	_, err := q.ExecContext(ctx, `UPDATE apple_edge.command_targets SET delivered_at = coalesce(delivered_at, now()) WHERE command_uuid = $1 AND enrollment_id = $2`, commandUUID, enrollmentID)
	return err
}

// MarkCompleted records a final result (Acknowledged, Error, CommandFormatError).
func MarkCompleted(ctx context.Context, q store.Querier, commandUUID, enrollmentID string) error {
	_, err := q.ExecContext(ctx, `UPDATE apple_edge.command_targets SET completed_at = coalesce(completed_at, now()), delivered_at = coalesce(delivered_at, now()) WHERE command_uuid = $1 AND enrollment_id = $2`, commandUUID, enrollmentID)
	return err
}

// CancelOpenTargets cancels the open targets of an enrollment (release).
func CancelOpenTargets(ctx context.Context, q store.Querier, enrollmentID string) error {
	_, err := q.ExecContext(ctx, `
UPDATE apple_edge.command_targets SET cancelled_at = now()
 WHERE enrollment_id = $1 AND completed_at IS NULL AND cancelled_at IS NULL AND expired_at IS NULL`, enrollmentID)
	return err
}

func nullIf(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
