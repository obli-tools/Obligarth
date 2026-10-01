package mdm

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
	"unicode"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"

	"github.com/MeeJay/Obligarth/apple-edge/internal/config"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ddm"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/queue"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store/nanomdmsql"
	"github.com/MeeJay/Obligarth/apple-edge/internal/tenant"
)

// Upstream is the part of NanoMDM's storage used to disable the
// enrollment of a tenant that loses a device identifier.
type Upstream interface {
	DisableEnrollment(ctx context.Context, deviceID string) error
}

// Guard sits between NanoMDM's HTTP handlers and certauth. It checks the
// topic, namespaces identifiers ("<key>_<id>") before certauth derives the
// enrollment id, applies the cross-tenant policy, and writes the outbox.
type Guard struct {
	next     service.CheckinAndCommandService
	upstream Upstream
	db       *sql.DB
	out      *outbox.Writer
	secrets  *store.Secrets
	policy   string
	logger   *obs.Logger
	metrics  *obs.Metrics
	holds    chan struct{}
	now      func() time.Time

	// namespace derives the stored identifiers; only tests replace it
	// (simulated upstream regression).
	namespace func(key, id string) string
}

// NewGuard returns the guard. poolSize bounds the transactions held open
// across an upstream call (a quarter of the pool) so that they can never
// starve the upstream storage of connections.
func NewGuard(next service.CheckinAndCommandService, upstream Upstream, db *sql.DB, out *outbox.Writer, secrets *store.Secrets,
	policy string, logger *obs.Logger, m *obs.Metrics, poolSize int) *Guard {
	return &Guard{next: next, upstream: upstream, db: db, out: out, secrets: secrets, policy: policy,
		logger: logger.With("component", "guard"), metrics: m, holds: make(chan struct{}, max(1, poolSize/4)),
		now: time.Now, namespace: ids.Namespace}
}

func httpErr(code int, msg string) error {
	return service.NewHTTPStatusError(code, errors.New(msg))
}

var (
	errBadIDs       = httpErr(http.StatusBadRequest, "invalid device identifiers")
	errTopic        = httpErr(http.StatusForbidden, "topic does not belong to the tenant")
	errConflict     = httpErr(http.StatusForbidden, "device identifier reserved by another tenant")
	errMismatch     = httpErr(http.StatusForbidden, "device does not match the enrollment challenge")
	errUnsupported  = httpErr(http.StatusBadRequest, "message not supported")
	errEndpoint     = httpErr(http.StatusBadRequest, "declarative management endpoint not allowed")
	errNoUserAuth   = httpErr(http.StatusGone, "user authentication not supported")
	errBusy         = httpErr(http.StatusServiceUnavailable, "busy")
	errMissingUUID  = httpErr(http.StatusBadRequest, "command result without CommandUUID")
	finalStatuses   = map[string]bool{"Acknowledged": true, "Error": true, "CommandFormatError": true}
	knownStatuses   = map[string]bool{"Idle": true, "NotNow": true, "Acknowledged": true, "Error": true, "CommandFormatError": true}
	errUnknownState = httpErr(http.StatusBadRequest, "unknown command status")
)

// prep is a validated, namespaced message.
type prep struct {
	st           *state
	t            *tenant.Tenant
	kind         string // udid or enrollment_id
	raw          string // device identifier as sent by the device
	deviceID     string // namespaced device channel id
	enrollmentID string // namespaced id of the channel (device or user)
	userChannel  bool
	enrollType   string
}

func validUserPart(s string) bool {
	if len(s) > 100 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ':' {
			return false
		}
	}
	return true
}

// prepare validates identifiers and the topic, then namespaces them.
func (g *Guard) prepare(r *mdm.Request, e *mdm.Enrollment, messageType, topic string, checkTopic bool) (*prep, error) {
	st := stateFrom(r.Context())
	if st == nil || st.tenant == nil {
		return nil, errNoState
	}
	p := &prep{st: st, t: st.tenant}
	switch {
	case e.UDID != "":
		p.kind, p.raw = store.KindUDID, e.UDID
	case e.EnrollmentID != "":
		p.kind, p.raw = store.KindEnrollmentID, e.EnrollmentID
	default:
		return nil, errBadIDs
	}
	if (e.UDID != "" && !ids.ValidRawID(e.UDID)) || (e.EnrollmentID != "" && !ids.ValidRawID(e.EnrollmentID)) ||
		!validUserPart(e.UserID) || !validUserPart(e.EnrollmentUserID) || !validUserPart(e.UserShortName) {
		return nil, errBadIDs
	}
	if checkTopic && !p.t.HasTopic(topic) {
		reason := "foreign_topic"
		if len(p.t.Topics) == 0 {
			reason = "no_push_certificate"
		}
		g.security(r.Context(), outbox.T(p.t.Key, "security.topic_mismatch", map[string]any{"reason": reason, "presented_topic": topic}))
		g.metrics.Checkins.Inc(p.t.Key, messageType, "refused_topic")
		return nil, errTopic
	}
	e.UDID = g.namespace(p.t.Key, e.UDID)
	e.EnrollmentID = g.namespace(p.t.Key, e.EnrollmentID)
	res := e.Resolved()
	if res == nil {
		return nil, errBadIDs
	}
	p.deviceID = res.DeviceChannelID
	p.enrollmentID = res.DeviceChannelID
	p.userChannel = res.IsUserChannel
	if res.IsUserChannel {
		p.enrollmentID += ":" + res.UserChannelID
	}
	p.enrollType = res.Type.String()
	return p, nil
}

// security emits a security event in its own transaction.
func (g *Guard) security(ctx context.Context, evs ...outbox.Event) {
	for _, ev := range evs {
		t := ev.Tenant
		if ev.Scope == outbox.ScopePlatform {
			t = "platform"
		}
		g.metrics.SecurityEvents.Inc(t, ev.Type)
	}
	if err := g.out.Emit(context.WithoutCancel(ctx), evs...); err != nil {
		g.logger.Error("msg", "security event", "err", err)
	}
}

// commit writes events (and fn's changes) in one transaction after the
// upstream processing, then schedules the outbox notification.
func (g *Guard) commit(ctx context.Context, fn func(tx *sql.Tx) ([]outbox.Event, error)) error {
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	evs, err := fn(tx)
	if err != nil {
		return err
	}
	if err := g.out.Insert(ctx, tx, evs...); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	g.out.Committed()
	return nil
}

func messageJSON(raw []byte) map[string]any {
	m, err := outbox.PlistToJSON(raw)
	if err != nil {
		return map[string]any{}
	}
	outbox.RedactSecrets(m)
	return m
}

func conflictEvents(requester, holder string, d Decision, kind, serial, policy string) []outbox.Event {
	req := map[string]any{"id_kind": kind, "outcome": d.RequesterOutcome}
	hold := map[string]any{"id_kind": kind, "outcome": d.HolderOutcome}
	if serial != "" {
		req["serial"], hold["serial"] = serial, serial
	}
	return []outbox.Event{
		outbox.T(requester, "security.device_id_conflict", req),
		outbox.T(holder, "security.device_id_conflict", hold),
		outbox.P("security.device_id_conflict", map[string]any{
			"id_kind": kind, "outcome": d.RequesterOutcome, "policy": policy,
			"tenants": map[string]string{"holder": holder, "requester": requester},
		}),
	}
}

// Authenticate checks the topic, the challenge binding and the
// cross-tenant policy, then lets certauth and NanoMDM store the enrollment.
func (g *Guard) Authenticate(r *mdm.Request, m *mdm.Authenticate) error {
	ctx := r.Context()
	p, err := g.prepare(r, &m.Enrollment, "Authenticate", m.Topic, true)
	if err != nil {
		return err
	}
	if p.userChannel {
		return errBadIDs
	}
	t := p.t
	ch, err := g.challengeOf(ctx, p)
	if err != nil {
		return err
	}
	if ch != nil {
		field := ""
		switch {
		case ch.BindUDID != "" && ch.BindUDID != p.raw:
			field = "udid"
		case ch.BindSerial != "" && ch.BindSerial != m.SerialNumber:
			field = "serial"
		}
		if field != "" {
			g.security(ctx, outbox.T(t.Key, "security.identity_mismatch", map[string]any{"field": field}).WithEnrollment(p.enrollmentID))
			g.metrics.Checkins.Inc(t.Key, "Authenticate", "refused_identity")
			return errMismatch
		}
	}
	proof, err := g.proof(ctx, t.Key, ch, p)
	if err != nil {
		return err
	}
	holder, err := store.ActiveDeviceID(ctx, g.db, p.kind, p.raw)
	if err != nil {
		return err
	}
	var transfer *store.Transfer
	if holder != nil && holder.Tenant != t.Key && p.kind == store.KindUDID {
		if transfer, err = store.FindTransfer(ctx, g.db, p.kind, p.raw, holder.Tenant, t.Key); err != nil {
			return err
		}
	}
	d := Decide(t.Key, p.kind, proof, g.policy, holder, transfer)
	if !d.Accept {
		g.security(ctx, conflictEvents(t.Key, holder.Tenant, d, p.kind, m.SerialNumber, g.policy)...)
		g.metrics.Checkins.Inc(t.Key, "Authenticate", "refused_conflict")
		return errConflict
	}
	if err := g.next.Authenticate(r, m); err != nil {
		return err
	}
	if d.Conflict && d.DisableHolder {
		if err := g.upstream.DisableEnrollment(ctx, holder.EnrollmentID); err != nil {
			return err
		}
	}
	msg := messageJSON(m.Raw)
	identity := map[string]any{}
	if is := p.st.issued; is != nil {
		identity["cert_sha256"] = is.SHA256
		identity["not_after"] = is.NotAfter.UTC().Format(time.RFC3339)
		identity["challenge_id"] = nilIfEmpty(is.ChallengeID)
	}
	if ch != nil {
		identity["session_ref"] = nilIfEmpty(ch.SessionRef)
	}
	err = g.commit(ctx, func(tx *sql.Tx) ([]outbox.Event, error) {
		var evs []outbox.Event
		if d.Conflict {
			if d.ReleaseReason != "" {
				released, err := store.ReleaseDeviceID(ctx, tx, holder.Tenant, p.kind, p.raw, d.ReleaseReason)
				if err != nil {
					return nil, err
				}
				if released {
					evs = append(evs, outbox.T(holder.Tenant, "device.id_released", map[string]any{"id_kind": p.kind, "reason": d.ReleaseReason}).WithEnrollment(holder.EnrollmentID))
				}
			}
			if d.Transfer != nil {
				if _, err := store.UseTransfer(ctx, tx, d.Transfer.ID); err != nil {
					return nil, err
				}
				evs = append(evs,
					outbox.T(t.Key, "device.transfer_completed", map[string]any{"direction": "in", "approval_ref": d.Transfer.ApprovalRef}).WithEnrollment(p.enrollmentID),
					outbox.T(holder.Tenant, "device.transfer_completed", map[string]any{"direction": "out", "approval_ref": d.Transfer.ApprovalRef}).WithEnrollment(holder.EnrollmentID),
					outbox.P("device.transfer_completed", map[string]any{"approval_ref": d.Transfer.ApprovalRef, "from": holder.Tenant, "to": t.Key}),
				)
			}
			evs = append(evs, conflictEvents(t.Key, holder.Tenant, d, p.kind, m.SerialNumber, g.policy)...)
		}
		evs = append(evs, outbox.T(t.Key, "mdm.authenticate", map[string]any{
			"device_id": p.raw, "enrollment_type": p.enrollType, "topic": m.Topic, "proof": proof,
			"identity": identity, "message": msg,
		}).WithEnrollment(p.enrollmentID))
		return evs, nil
	})
	if err != nil {
		return err
	}
	g.metrics.Checkins.Inc(t.Key, "Authenticate", "ok")
	return nil
}

// proof returns "ade" when the identity was issued on a challenge bound to
// a MachineInfo signed by Apple for this UDID whose serial number is an
// ADE device of the tenant: such a device is in the Setup Assistant of the
// tenant, hence erased, and its proof prevails over a reservation elsewhere.
func (g *Guard) proof(ctx context.Context, tenant string, ch *store.Challenge, p *prep) (string, error) {
	if ch == nil || ch.MachineInfoID == "" || p.kind != store.KindUDID {
		return store.ProofNone, nil
	}
	ok, err := store.ADEProof(ctx, g.db, tenant, ch.MachineInfoID, p.raw)
	if err != nil || !ok {
		return store.ProofNone, err
	}
	return store.ProofADE, nil
}

// challengeOf returns the challenge of the identity of the request, if any.
func (g *Guard) challengeOf(ctx context.Context, p *prep) (*store.Challenge, error) {
	if p.st.issued == nil {
		return nil, nil
	}
	return store.ChallengeByID(ctx, g.db, p.t.Key, p.st.issued.ChallengeID)
}

// TokenUpdate activates the identifier in the registry (device channel)
// before NanoMDM stores the token: a concurrent enrollment of the same
// identifier in another tenant fails on the unique index and is refused.
func (g *Guard) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	ctx := r.Context()
	p, err := g.prepare(r, &m.Enrollment, "TokenUpdate", m.Topic, true)
	if err != nil {
		return err
	}
	t := p.t
	msg := messageJSON(m.Raw)
	hadUnlock := len(m.UnlockToken) > 0
	outbox.RedactTokenUpdate(msg)
	awaiting, _ := msg["AwaitingConfiguration"].(bool)
	channel := "device"
	if p.userChannel {
		channel = "user"
	}
	events := func(tx *sql.Tx) ([]outbox.Event, error) {
		tally, err := nanomdmsql.TokenUpdateTally(ctx, tx, p.enrollmentID)
		if err != nil {
			return nil, err
		}
		return []outbox.Event{outbox.T(t.Key, "mdm.token_update", map[string]any{
			"device_id": p.raw, "channel": channel, "awaiting_configuration": awaiting,
			"token_update_tally": tally, "has_unlock_token": hadUnlock, "topic": m.Topic, "message": msg,
		}).WithEnrollment(p.enrollmentID)}, nil
	}
	if p.userChannel {
		if err := g.next.TokenUpdate(r, m); err != nil {
			return err
		}
		if err := g.commit(ctx, events); err != nil {
			return err
		}
		g.metrics.Checkins.Inc(t.Key, "TokenUpdate", "ok")
		return nil
	}
	ch, err := g.challengeOf(ctx, p)
	if err != nil {
		return err
	}
	proof, err := g.proof(ctx, t.Key, ch, p)
	if err != nil {
		return err
	}
	select {
	case g.holds <- struct{}{}:
		defer func() { <-g.holds }()
	case <-ctx.Done():
		return errBusy
	}
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	activated := true
	if err := store.ActivateDeviceID(ctx, tx, t.Key, p.kind, p.raw, p.deviceID, proof); err != nil {
		_ = tx.Rollback()
		switch {
		case errors.Is(err, store.ErrIDConflict):
			holder, herr := store.ActiveDeviceID(ctx, g.db, p.kind, p.raw)
			if herr != nil {
				return herr
			}
			if holder == nil { // released in the meantime: let the device retry
				return errBusy
			}
			if g.policy == config.PolicyAllow && p.kind == store.KindUDID {
				activated = false
				if tx, err = g.db.BeginTx(ctx, nil); err != nil {
					return err
				}
				defer tx.Rollback()
				break
			}
			d := Decision{Conflict: true, RequesterOutcome: OutcomeRefused, HolderOutcome: OutcomeKept}
			g.security(ctx, conflictEvents(t.Key, holder.Tenant, d, p.kind, "", g.policy)...)
			g.metrics.Checkins.Inc(t.Key, "TokenUpdate", "refused_conflict")
			return errConflict
		case store.IsLockTimeout(err):
			return errBusy
		default:
			return err
		}
	}
	if err := g.next.TokenUpdate(r, m); err != nil {
		return err
	}
	evs, err := events(tx)
	if err != nil {
		return err
	}
	if err := g.out.Insert(ctx, tx, evs...); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	g.out.Committed()
	outcome := "ok"
	if !activated {
		outcome = "ok_not_registered"
	}
	g.metrics.Checkins.Inc(t.Key, "TokenUpdate", outcome)
	return nil
}

// CheckOut releases the identifier of the device channel.
func (g *Guard) CheckOut(r *mdm.Request, m *mdm.CheckOut) error {
	ctx := r.Context()
	p, err := g.prepare(r, &m.Enrollment, "CheckOut", "", false)
	if err != nil {
		return err
	}
	if err := g.next.CheckOut(r, m); err != nil {
		return err
	}
	err = g.commit(ctx, func(tx *sql.Tx) ([]outbox.Event, error) {
		evs := []outbox.Event{outbox.T(p.t.Key, "mdm.checkout", map[string]any{"device_id": p.raw}).WithEnrollment(p.enrollmentID)}
		if !p.userChannel {
			released, err := store.ReleaseDeviceID(ctx, tx, p.t.Key, p.kind, p.raw, "checkout")
			if err != nil {
				return nil, err
			}
			if released {
				evs = append(evs, outbox.T(p.t.Key, "device.id_released", map[string]any{"id_kind": p.kind, "reason": "checkout"}).WithEnrollment(p.enrollmentID))
			}
		}
		return evs, nil
	})
	if err == nil {
		g.metrics.Checkins.Inc(p.t.Key, "CheckOut", "ok")
	}
	return err
}

// SetBootstrapToken stores the token encrypted (storage wrapper).
func (g *Guard) SetBootstrapToken(r *mdm.Request, m *mdm.SetBootstrapToken) error {
	if _, err := g.prepare(r, &m.Enrollment, "SetBootstrapToken", "", false); err != nil {
		return err
	}
	return g.next.SetBootstrapToken(r, m)
}

// GetBootstrapToken returns the escrowed token.
func (g *Guard) GetBootstrapToken(r *mdm.Request, m *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	if _, err := g.prepare(r, &m.Enrollment, "GetBootstrapToken", "", false); err != nil {
		return nil, err
	}
	return g.next.GetBootstrapToken(r, m)
}

// UserAuthenticate is not supported: 410 tells the device not to create
// the user channel.
func (g *Guard) UserAuthenticate(r *mdm.Request, m *mdm.UserAuthenticate) ([]byte, error) {
	if _, err := g.prepare(r, &m.Enrollment, "UserAuthenticate", "", false); err != nil {
		return nil, err
	}
	return nil, errNoUserAuth
}

// DeclarativeManagement checks the endpoint against the allow-list, then
// lets certauth and the NanoMDM core hand the check-in to the DDM relay.
func (g *Guard) DeclarativeManagement(r *mdm.Request, m *mdm.DeclarativeManagement) ([]byte, error) {
	p, err := g.prepare(r, &m.Enrollment, "DeclarativeManagement", "", false)
	if err != nil {
		return nil, err
	}
	if !ddm.ValidEndpoint(m.Endpoint) {
		g.metrics.Checkins.Inc(p.t.Key, "DeclarativeManagement", "refused_endpoint")
		g.metrics.DDMRelay.Inc(p.t.Key, "invalid", "invalid_endpoint")
		return nil, errEndpoint
	}
	out, err := g.next.DeclarativeManagement(r, m)
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	g.metrics.Checkins.Inc(p.t.Key, "DeclarativeManagement", outcome)
	return out, err
}

// GetToken is not supported.
func (g *Guard) GetToken(r *mdm.Request, m *mdm.GetToken) (*mdm.GetTokenResponse, error) {
	return nil, errUnsupported
}

// CommandAndReportResults records the result (outbox) and delivers the next
// command, injecting its secret, unless commands are frozen.
func (g *Guard) CommandAndReportResults(r *mdm.Request, res *mdm.CommandResults) (*mdm.Command, error) {
	ctx := r.Context()
	p, err := g.prepare(r, &res.Enrollment, "", "", false)
	if err != nil {
		return nil, err
	}
	t := p.t
	if !knownStatuses[res.Status] {
		return nil, errUnknownState
	}
	forUpstream := res
	var result *outbox.Event
	if res.Status != "Idle" {
		if res.CommandUUID == "" {
			return nil, errMissingUUID
		}
		ev, upstreamKnows, err := g.resultEvent(ctx, p, res)
		if err != nil {
			return nil, err
		}
		result = ev
		if !upstreamKnows {
			// Unknown upstream (already closed, or never sent to this
			// enrollment): NanoMDM only records a presence.
			c := *res
			c.Status, c.CommandUUID = "Idle", ""
			forUpstream = &c
		}
		g.metrics.CommandResults.Inc(t.Key, res.Status)
	}
	cmd, err := g.next.CommandAndReportResults(r, forUpstream)
	if err != nil {
		return nil, err
	}
	if cmd != nil && t.CommandsFrozen {
		cmd = nil
	}
	var delivered *mdm.Command
	err = g.commit(ctx, func(tx *sql.Tx) ([]outbox.Event, error) {
		var evs []outbox.Event
		if result != nil {
			evs = append(evs, *result)
			if finalStatuses[res.Status] {
				if err := queue.MarkCompleted(ctx, tx, res.CommandUUID, p.enrollmentID); err != nil {
					return nil, err
				}
			}
		}
		if cmd != nil {
			out, reqType, err := g.prepareDelivery(ctx, tx, p, cmd)
			if err != nil {
				return nil, err
			}
			delivered = out
			evs = append(evs, outbox.T(t.Key, "mdm.command_delivered", map[string]any{"device_id": p.raw, "request_type": reqType}).
				WithEnrollment(p.enrollmentID).WithCommand(cmd.CommandUUID))
		}
		return evs, nil
	})
	if err != nil {
		return nil, err
	}
	return delivered, nil
}

// resultEvent builds the mdm.command_result event. The result must belong
// to a command queued for this enrollment, upstream or in the business
// view (a result whose command NanoMDM already closed is still reported:
// the device resends results that were not acknowledged by a 200).
func (g *Guard) resultEvent(ctx context.Context, p *prep, res *mdm.CommandResults) (*outbox.Event, bool, error) {
	reqType, upstreamKnows, err := nanomdmsql.QueuedFor(ctx, g.db, p.enrollmentID, res.CommandUUID)
	if err != nil {
		return nil, false, err
	}
	info, found, err := queue.Info(ctx, g.db, res.CommandUUID)
	if err != nil {
		return nil, false, err
	}
	if found && info.Tenant != p.t.Key {
		found = false
	}
	if found {
		reqType = info.RequestType
	}
	if !upstreamKnows && found {
		var open bool
		if err := g.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM apple_edge.command_targets WHERE command_uuid = $1 AND enrollment_id = $2)`,
			res.CommandUUID, p.enrollmentID).Scan(&open); err != nil {
			return nil, false, err
		}
		found = open
	}
	if !upstreamKnows && !found {
		g.metrics.SecurityEvents.Inc(p.t.Key, "unknown_command_result")
		return nil, false, nil
	}
	converted, err := outbox.PlistToJSON(res.Raw)
	if err != nil {
		converted = map[string]any{}
	}
	if code, ok := converted["ActivationLockBypassCode"].(string); ok && code != "" && !p.userChannel {
		ref, err := g.secrets.Put(ctx, p.t.Key, p.deviceID, store.SecretBypassCode, []byte(code))
		if err != nil {
			return nil, false, err
		}
		converted["ActivationLockBypassCode"] = outbox.SecretRef(ref)
	}
	errorChain, result := outbox.SplitResult(converted)
	outbox.RedactSecrets(result)
	payload := map[string]any{"device_id": p.raw, "status": res.Status, "request_type": reqType, "result": result}
	if errorChain != nil {
		payload["error_chain"] = errorChain
	}
	ev := outbox.T(p.t.Key, "mdm.command_result", payload).WithEnrollment(p.enrollmentID).WithCommand(res.CommandUUID)
	return &ev, upstreamKnows, nil
}

// prepareDelivery records the delivery and injects the command's secret.
func (g *Guard) prepareDelivery(ctx context.Context, tx *sql.Tx, p *prep, cmd *mdm.Command) (*mdm.Command, string, error) {
	info, found, err := queue.Info(ctx, tx, cmd.CommandUUID)
	if err != nil {
		return nil, "", err
	}
	reqType := cmd.Command.RequestType
	if !found || info.Tenant != p.t.Key {
		g.logger.Info("msg", "delivering a command without business record", "tenant", p.t.Key, "command_uuid", cmd.CommandUUID)
		return cmd, reqType, nil
	}
	if err := queue.MarkDelivered(ctx, tx, cmd.CommandUUID, p.enrollmentID); err != nil {
		return nil, "", err
	}
	out := cmd
	if info.SecretKind == store.SecretUnlockToken {
		_, secret, err := g.secrets.Current(ctx, p.t.Key, p.deviceID, store.SecretUnlockToken)
		if err != nil {
			g.logger.Error("msg", "secret unavailable at delivery", "tenant", p.t.Key, "command_uuid", cmd.CommandUUID, "err", err)
		} else if raw, ok := queue.InjectSecret(cmd.Raw, secret); ok {
			c := *cmd
			c.Raw = raw
			out = &c
		}
	}
	return out, reqType, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
