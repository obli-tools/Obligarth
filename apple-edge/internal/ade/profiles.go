package ade

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/micromdm/nanodep/godep"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// UsageRe is the format of a profile usage (corporate, kiosk...).
var UsageRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Assignment limits.
const (
	MaxSerials   = 1000
	assignChunk  = 500
	maxProfileSz = 256 << 10
)

// TenantURL reports whether raw is an absolute URL of the device surface
// of tenant: same scheme and host as publicBase, path under /t/<key>/,
// without dot segments, credentials or fragment.
func TenantURL(publicBase, tenant, raw string) bool {
	base, err := url.Parse(publicBase)
	if err != nil {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) {
		return false
	}
	prefix := "/t/" + tenant + "/"
	if !strings.HasPrefix(u.EscapedPath(), prefix) || strings.Contains(u.Path, "\\") {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return strings.HasPrefix(path.Clean(u.Path)+"/", prefix)
}

// errTokenNotActive is returned when Apple's API cannot be called.
var errTokenNotActive = apierr.Conflict("ade_token_not_active", "the ADE token is not active")

func (s *Service) activeToken(ctx context.Context, tenant, id string) error {
	if err := liveTenant(ctx, s.DB, tenant, false); err != nil {
		return err
	}
	t, err := s.tokenRow(ctx, s.DB, tenant, id, false)
	if err != nil {
		return err
	}
	if t.State != StateActive {
		return errTokenNotActive
	}
	return nil
}

// apiError maps an ADE API failure onto an internal API error.
func (s *Service) apiError(tenant, id string, err error) error {
	kind, code := Classify(err)
	s.Logger.Info("msg", "ADE API call", "component", "ade", "tenant", tenant, "ade_token", id, "outcome", code, "err", err)
	switch kind {
	case KindTransient:
		return apierr.New(http.StatusBadGateway, "ade_unavailable", "the ADE API did not answer, try again")
	case KindRejected:
		return apierr.Unprocessable("ade_rejected", "Apple refused the request ("+code+")")
	}
	return apierr.Conflict("ade_token_unusable", "Apple refused the token ("+code+")")
}

// ProfileResult is the answer of PUT .../profiles/{usage}.
type ProfileResult struct {
	Usage       string `json:"usage"`
	ProfileUUID string `json:"profile_uuid"`
	IsDefault   bool   `json:"is_default"`
}

// DefineProfile defines (or redefines) the ADE profile of a usage: its
// enrollment URLs must belong to the tenant, await_device_configured is
// forced. Devices that want this usage get the new profile at the next
// cycle of the loop, which is woken up.
func (s *Service) DefineProfile(ctx context.Context, tenant, id, usage string, profile map[string]any, isDefault bool) (ProfileResult, error) {
	if !UsageRe.MatchString(usage) {
		return ProfileResult{}, apierr.BadRequest("usage must match ^[a-z][a-z0-9_]{0,31}$")
	}
	if len(profile) == 0 {
		return ProfileResult{}, apierr.BadRequest("profile is required")
	}
	u, ok := profile["url"].(string)
	if !ok || !TenantURL(s.PublicBase, tenant, u) {
		return ProfileResult{}, apierr.Unprocessable("url_outside_tenant", "url must be an URL of this tenant (MDM_PUBLIC_BASE/t/<key>/...)")
	}
	if v, present := profile["configuration_web_url"]; present {
		if w, ok := v.(string); !ok || !TenantURL(s.PublicBase, tenant, w) {
			return ProfileResult{}, apierr.Unprocessable("url_outside_tenant", "configuration_web_url must be an URL of this tenant")
		}
	}
	if d, present := profile["devices"]; present {
		if list, ok := d.([]any); !ok || len(list) > 0 {
			return ProfileResult{}, apierr.Unprocessable("validation_failed", "assign devices with POST .../assignments, not in the profile")
		}
		delete(profile, "devices")
	}
	profile["await_device_configured"] = true
	raw, err := json.Marshal(profile)
	if err != nil || len(raw) > maxProfileSz {
		return ProfileResult{}, apierr.BadRequest("profile is not valid JSON or too large")
	}
	if err := s.activeToken(ctx, tenant, id); err != nil {
		return ProfileResult{}, err
	}
	var resp godep.DefineProfileResponse
	if err := s.Client().Do(ctx, id, http.MethodPost, "/profile", json.RawMessage(raw), &resp); err != nil {
		return ProfileResult{}, s.apiError(tenant, id, err)
	}
	if resp.ProfileUUID == nil || *resp.ProfileUUID == "" {
		return ProfileResult{}, apierr.New(http.StatusBadGateway, "ade_unavailable", "the ADE API returned no profile UUID")
	}
	res := ProfileResult{Usage: usage, ProfileUUID: *resp.ProfileUUID, IsDefault: isDefault}
	err = store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		if _, err := s.tokenRow(ctx, tx, tenant, id, true); err != nil {
			return err
		}
		if isDefault {
			if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.ade_profiles SET is_default = false WHERE token_id = $1 AND usage <> $2 AND is_default`, id, usage); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.ade_profiles (token_id, usage, profile_json, profile_uuid, is_default, defined_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (token_id, usage) DO UPDATE SET profile_json = EXCLUDED.profile_json, profile_uuid = EXCLUDED.profile_uuid,
    is_default = EXCLUDED.is_default, defined_at = EXCLUDED.defined_at`, id, usage, string(raw), res.ProfileUUID, isDefault); err != nil {
			return err
		}
		return store.Notify(ctx, tx, Channel, id)
	})
	return res, err
}

// AssignResult is the answer of POST .../assignments.
type AssignResult struct {
	Usage       string            `json:"usage"`
	ProfileUUID string            `json:"profile_uuid"`
	Results     map[string]string `json:"results"`
}

// Assign assigns the profile of a usage to serial numbers (kiosks...) and
// remembers the choice (wanted_usage) for later reassignments.
func (s *Service) Assign(ctx context.Context, tenant, id, usage string, serials []string) (AssignResult, error) {
	if !UsageRe.MatchString(usage) {
		return AssignResult{}, apierr.BadRequest("usage is invalid")
	}
	serials = slices.Compact(slices.Sorted(slices.Values(serials)))
	if len(serials) == 0 || len(serials) > MaxSerials {
		return AssignResult{}, apierr.BadRequest("serials must hold 1 to 1000 serial numbers")
	}
	for _, sn := range serials {
		if !SerialRe.MatchString(sn) {
			return AssignResult{}, apierr.BadRequest("invalid serial number")
		}
	}
	if err := s.activeToken(ctx, tenant, id); err != nil {
		return AssignResult{}, err
	}
	var uuid sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT profile_uuid FROM apple_edge.ade_profiles WHERE token_id = $1 AND usage = $2`, id, usage).Scan(&uuid)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !uuid.Valid) {
		return AssignResult{}, apierr.Unprocessable("unknown_usage", "no profile is defined for this usage")
	}
	if err != nil {
		return AssignResult{}, err
	}
	res := AssignResult{Usage: usage, ProfileUUID: uuid.String, Results: map[string]string{}}
	for start := 0; start < len(serials); start += assignChunk {
		chunk := serials[start:min(start+assignChunk, len(serials))]
		resp, err := s.Client().AssignProfile(ctx, id, uuid.String, chunk...)
		if err != nil {
			return res, s.apiError(tenant, id, err)
		}
		results := map[string]string{}
		for _, sn := range chunk {
			results[sn] = string(resp.Devices[sn])
			res.Results[sn] = results[sn]
		}
		if err := s.recordAssignment(ctx, tenant, id, usage, uuid.String, results, true); err != nil {
			return res, err
		}
	}
	return res, nil
}

// recordAssignment stores the outcome of AssignProfile and its event.
// explicit marks a choice of the brain (wanted_usage).
func (s *Service) recordAssignment(ctx context.Context, tenant, id, usage, uuid string, results map[string]string, explicit bool) error {
	err := store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		for sn, st := range results {
			switch {
			case st == "SUCCESS" && explicit:
				_, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.ade_devices (token_id, serial, tenant_key, profile_uuid, profile_status, wanted_usage)
VALUES ($1, $2, $3, $4, 'assigned', $5)
ON CONFLICT (token_id, serial) DO UPDATE SET profile_uuid = EXCLUDED.profile_uuid, profile_status = 'assigned',
    wanted_usage = EXCLUDED.wanted_usage, updated_at = now()`, id, sn, tenant, uuid, usage)
				if err != nil {
					return err
				}
			case st == "SUCCESS":
				if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.ade_devices SET profile_uuid = $3, profile_status = 'assigned' WHERE token_id = $1 AND serial = $2`, id, sn, uuid); err != nil {
					return err
				}
			case explicit:
				if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.ade_devices SET wanted_usage = $3, updated_at = now() WHERE token_id = $1 AND serial = $2`, id, sn, usage); err != nil {
					return err
				}
			}
		}
		return s.Out.Insert(ctx, tx, outbox.T(tenant, "ade.profile_assignment", map[string]any{
			"token_id": id, "usage": usage, "profile_uuid": uuid, "results": results,
		}))
	})
	if err == nil {
		s.Out.Committed()
	}
	return err
}

// AccountDrivenEnrollment declares the BYOD service discovery URL of the
// tenant (MDM_PUBLIC_BASE/t/<key>/byod/discovery, served by the brain).
func (s *Service) AccountDrivenEnrollment(ctx context.Context, tenant, id string) (string, error) {
	if err := s.activeToken(ctx, tenant, id); err != nil {
		return "", err
	}
	u := s.PublicBase + "/t/" + tenant + "/byod/discovery"
	if err := s.Client().AssignAccountDrivenEnrollmentProfile(ctx, id, u); err != nil {
		return "", s.apiError(tenant, id, err)
	}
	return u, nil
}
