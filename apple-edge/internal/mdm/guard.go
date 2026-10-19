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
	"github.com/micromdm/nanomdm/service/certauth"
	"github.com/micromdm/plist"

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
	errKindConflict = httpErr(http.StatusForbidden, "device identifier reserved")
	errMismatch     = httpErr(http.StatusForbidden, "device does not match the enrollment challenge")
	errUnsupported  = httpErr(http.StatusBadRequest, "message not supported")
	errEndpoint     = httpErr(http.StatusBadRequest, "declarative management endpoint not allowed")
	errNoUserAuth   = httpErr(http.StatusGone, "user authentication not supported")
	errBusy         = httpErr(http.StatusServiceUnavailable, "busy")
	errMissingUUID  = httpErr(http.StatusBadRequest, "command result without CommandUUID")
	errNotBound     = httpErr(http.StatusForbidden, "device identity not bound to the enrollment")
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

// kindConflictEvent tells the tenant that the identifier of its device
// channel is held under the other kind (UDID or EnrollmentID). It names
// the enrollment (the brain's record of that channel gets a timeline
// entry) and nothing else of the device. A superseded identifier of the
// other kind gets no device.id_released: that event names the same
// enrollment, which now belongs to the ADE device; the brain detaches the
// record of the other kind itself when it consumes the Authenticate.
func kindConflictEvent(tenant string, p *prep, outcome string) outbox.Event {
	return outbox.T(tenant, "security.device_id_conflict", map[string]any{"id_kind": p.kind, "outcome": outcome}).WithEnrollment(p.enrollmentID)
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
	// The other kind of identifier (decision MDM-B2-R13, option A): a UDID
	// and an EnrollmentID share the device channel "<key>_<id>", so a User
	// Enrollment whose EnrollmentID is the UDID of an enrolled device of the
	// tenant (or an OTA enrollment announcing as UDID the EnrollmentID of a
	// User Enrollment) would take its enrollment. Refused, unless the ADE
	// proof of this Authenticate prevails: the other identifier is then
	// released (INT-B3-R3, option A). The identifier "exists" under the
	// other kind when it is active, and also while an Authenticate of the
	// other kind accepted on the channel awaits its TokenUpdate (review of
	// lot C0, AE-C0-R1): the first device to authenticate holds the channel
	// until its identifier is released. Authenticates of a device channel
	// are serialised by its advisory lock, held across the upstream call
	// and up to the commit, so that two of them never both pass the check.
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
	if err := lockDeviceChannel(ctx, tx, p.deviceID); err != nil {
		return err
	}
	otherKind, err := store.ActiveDeviceIDIn(ctx, tx, t.Key, store.OtherKind(p.kind), p.raw)
	if err != nil {
		return err
	}
	if proof != store.ProofADE {
		refuse := otherKind != nil
		if !refuse {
			if refuse, err = g.pendingOtherKind(ctx, tx, p); err != nil {
				return err
			}
		}
		if refuse {
			_ = tx.Rollback()
			g.security(ctx, kindConflictEvent(t.Key, p, OutcomeRefusedOtherKind))
			g.metrics.Checkins.Inc(t.Key, "Authenticate", "refused_kind")
			return errKindConflict
		}
	}
	holder, err := store.ActiveDeviceID(ctx, tx, p.kind, p.raw)
	if err != nil {
		return err
	}
	// The same kind, active in this tenant, without ADE proof (decision of the
	// owners of 19/10/2026 on AE-C0-R2bis, option C of MDM-B2-R13): NanoMDM
	// would disable the managed device's enrollment and take its push token.
	// Accepted only for the identity certificate already associated with the
	// enrollment (the same device authenticating again), or under a
	// re-enrollment allowance of the brain ("Allow the re-enrollment" on the
	// record), consumed here; refused otherwise (403, security event).
	reenrollAllowed := false
	if proof != store.ProofADE && holder != nil && holder.Tenant == t.Key {
		same := false
		if is := p.st.issued; is != nil && is.SHA256 != "" {
			hashes, err := nanomdmsql.CertHashes(ctx, tx, p.deviceID)
			if err != nil {
				return err
			}
			for _, h := range hashes {
				if h == is.SHA256 {
					same = true
					break
				}
			}
		}
		if !same {
			if reenrollAllowed, err = store.TakeReenrollAllowance(ctx, tx, t.Key, p.kind, p.raw); err != nil {
				return err
			}
			if !reenrollAllowed {
				_ = tx.Rollback()
				g.security(ctx, kindConflictEvent(t.Key, p, OutcomeRefusedReenroll))
				g.metrics.Checkins.Inc(t.Key, "Authenticate", "refused_reenroll")
				return errKindConflict
			}
		}
	}
	var transfer *store.Transfer
	if holder != nil && holder.Tenant != t.Key && p.kind == store.KindUDID {
		if transfer, err = store.FindTransfer(ctx, g.db, p.kind, p.raw, holder.Tenant, t.Key); err != nil {
			return err
		}
	}
	d := Decide(t.Key, p.kind, proof, g.policy, holder, transfer)
	if !d.Accept {
		_ = tx.Rollback()
		g.security(ctx, conflictEvents(t.Key, holder.Tenant, d, p.kind, m.SerialNumber, g.policy)...)
		g.metrics.Checkins.Inc(t.Key, "Authenticate", "refused_conflict")
		return errConflict
	}
	if err := g.next.Authenticate(r, m); err != nil {
		return upstreamErr(err)
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
	evs, err := func() ([]outbox.Event, error) {
		var evs []outbox.Event
		// Under the ADE proof, the identity of this Authenticate is the only
		// one of the enrollment from now on (lot C0): a squatter's identity
		// no longer answers. Without proof, the other associations stay until
		// the identifier is activated anew (TokenUpdate): an Authenticate
		// alone never cuts a device off (review of lot C0, AE-C0-R1). A
		// re-enrollment without proof of an active identifier is refused above
		// unless the brain allowed it (decision of the owners of 19/10/2026 on
		// AE-C0-R2bis): an allowed one replaces the previous identity, as the
		// ADE proof does (the operator decided the record is this device's).
		if is := p.st.issued; (proof == store.ProofADE || reenrollAllowed) && is != nil && is.SHA256 != "" {
			if _, err := nanomdmsql.DropOtherCertHashes(ctx, tx, p.deviceID, is.SHA256); err != nil {
				return nil, err
			}
		}
		if otherKind != nil {
			released, err := store.ReleaseDeviceID(ctx, tx, t.Key, otherKind.Kind, p.raw, "superseded_by_proof")
			if err != nil {
				return nil, err
			}
			if released {
				evs = append(evs, kindConflictEvent(t.Key, p, OutcomeSupersededOtherKind))
			}
		}
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
		auth := map[string]any{
			"device_id": p.raw, "enrollment_type": p.enrollType, "topic": m.Topic, "proof": proof,
			"identity": identity, "message": msg,
		}
		if reenrollAllowed {
			auth["reenroll"] = "allowed"
		}
		evs = append(evs, outbox.T(t.Key, "mdm.authenticate", auth).WithEnrollment(p.enrollmentID))
		return evs, nil
	}()
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
			return upstreamErr(err)
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
	// The lock of the device channel orders the Authenticates and the
	// activations of both kinds (MDM-B2-R13): taken first, before any row.
	if err := lockDeviceChannel(ctx, tx, p.deviceID); err != nil {
		return err
	}
	wasActive, err := store.ActiveDeviceIDIn(ctx, tx, t.Key, p.kind, p.raw)
	if err != nil {
		return err
	}
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
				if err := lockDeviceChannel(ctx, tx, p.deviceID); err != nil {
					return err
				}
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
	// The other kind of identifier, as at Authenticate (MDM-B2-R13): under
	// the lock of the device channel, the later of two activations of both
	// kinds sees the earlier one committed.
	var kindEvents []outbox.Event
	otherKind, err := store.ActiveDeviceIDIn(ctx, tx, t.Key, store.OtherKind(p.kind), p.raw)
	if err != nil {
		return err
	}
	if otherKind != nil {
		if proof != store.ProofADE {
			_ = tx.Rollback()
			g.security(ctx, kindConflictEvent(t.Key, p, OutcomeRefusedOtherKind))
			g.metrics.Checkins.Inc(t.Key, "TokenUpdate", "refused_kind")
			return errKindConflict
		}
		released, err := store.ReleaseDeviceID(ctx, tx, t.Key, otherKind.Kind, p.raw, "superseded_by_proof")
		if err != nil {
			return err
		}
		if released {
			kindEvents = append(kindEvents, kindConflictEvent(t.Key, p, OutcomeSupersededOtherKind))
		}
	}
	if err := g.next.TokenUpdate(r, m); err != nil {
		return upstreamErr(err)
	}
	// The identifier activated anew: the identity of this TokenUpdate is the
	// only one of the enrollment from now on (lot C0). An Authenticate on the
	// channel that did not reach its TokenUpdate, or the identity of a holder
	// whose identifier was released, no longer answers.
	if activated && wasActive == nil && p.st.certSHA != "" {
		if _, err := nanomdmsql.DropOtherCertHashes(ctx, tx, p.deviceID, p.st.certSHA); err != nil {
			return err
		}
	}
	evs, err := events(tx)
	if err != nil {
		return err
	}
	evs = append(kindEvents, evs...)
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
		return upstreamErr(err)
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
	return upstreamErr(g.next.SetBootstrapToken(r, m))
}

// GetBootstrapToken returns the escrowed token.
func (g *Guard) GetBootstrapToken(r *mdm.Request, m *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	if _, err := g.prepare(r, &m.Enrollment, "GetBootstrapToken", "", false); err != nil {
		return nil, err
	}
	tok, err := g.next.GetBootstrapToken(r, m)
	return tok, upstreamErr(err)
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
	err = upstreamErr(err)
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
		return nil, upstreamErr(err)
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

// upstreamErr translates the refusals of certauth (an identity that is not,
// or no longer, bound to the enrollment: its association was removed when
// another identity activated the identifier) into a 403; NanoMDM would
// answer 500 (review of lot C0, AE-C0-R4).
func upstreamErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, certauth.ErrNoCertAssoc) || errors.Is(err, certauth.ErrNoCertReuse) || errors.Is(err, certauth.ErrMissingCert) {
		return errNotBound
	}
	return err
}

// lockDeviceChannel takes the advisory lock of a device channel for the
// transaction: Authenticates and activations of the channel, of both kinds
// of identifier, are serialised by it.
func lockDeviceChannel(ctx context.Context, tx *sql.Tx, deviceID string) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "device_channel:"+deviceID); err != nil {
		if store.IsLockTimeout(err) {
			return errBusy
		}
		return err
	}
	return nil
}

// pendingOtherKind reports whether the last Authenticate NanoMDM stored for
// the device channel announced the other kind of identifier, and the
// identifier of that kind was not released since: a device of the other
// kind authenticated on the channel and awaits (or skipped) its
// TokenUpdate. The first device to authenticate keeps the channel (review
// of lot C0, AE-C0-R1); only an ADE proof, or the release of the identifier
// (CheckOut, retirement), lets the other kind in.
func (g *Guard) pendingOtherKind(ctx context.Context, q nanomdmsql.Querier, p *prep) (bool, error) {
	other := store.OtherKind(p.kind)
	raw, releasedAfter, found, err := nanomdmsql.LastAuthenticate(ctx, q, p.deviceID, p.t.Key, other, p.raw)
	if err != nil || !found || releasedAfter {
		return false, err
	}
	var last struct {
		UDID         string
		EnrollmentID string
	}
	if err := plist.Unmarshal(raw, &last); err != nil {
		// Stored by NanoMDM from a message the guard accepted: unreadable
		// means corrupted, refuse rather than guess.
		g.logger.Error("msg", "stored Authenticate unreadable", "tenant", p.t.Key, "err", err)
		return true, nil
	}
	switch other {
	case store.KindUDID:
		return last.UDID != "", nil
	default:
		return last.UDID == "" && last.EnrollmentID != "", nil
	}
}
