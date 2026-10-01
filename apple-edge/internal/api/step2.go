package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MeeJay/Obligarth/apple-edge/internal/ade"
	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/signing"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store/nanomdmsql"
)

// PushWait bounds the wait for push outcomes in an API call; pushes still
// queued then are reported "deferred" and sent later.
const PushWait = 5 * time.Second

// Maximum number of enrollments of one push request.
const maxPushTargets = 10000

// ------------------------------------------------------------------- APNs

func (s *Server) pushCSR(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	csr, err := s.Tenants.NewPushCSR(r.Context(), key)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, csr)
}

func (s *Server) pushRequests(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req struct {
		EnrollmentIDs []string `json:"enrollment_ids"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	targets := slices.Compact(slices.Sorted(slices.Values(req.EnrollmentIDs)))
	if len(targets) == 0 || len(targets) > maxPushTargets {
		return apierr.BadRequest("enrollment_ids must hold 1 to 10000 enrollment ids")
	}
	for _, t := range targets {
		if !ids.BelongsTo(key, t) {
			return apierr.Unprocessable("target_outside_tenant", "every enrollment must belong to this tenant")
		}
	}
	if _, err := s.liveTenant(r, key); err != nil {
		return err
	}
	enabled, err := nanomdmsql.EnabledEnrollments(r.Context(), s.DB, targets)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if !enabled[t] {
			return apierr.Unprocessable("target_outside_tenant", "every enrollment must be an enabled enrollment of this tenant")
		}
	}
	results := s.Push.Push(r.Context(), key, targets, PushWait)
	return writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// ------------------------------------------------------------------- CA

func (s *Server) rotateCA(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	rot, err := s.Tenants.RotateCA(r.Context(), key)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, rot)
}

// ------------------------------------------------------------- MachineInfo

func (s *Server) verifyMachineInfo(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req struct {
		MachineInfo string `json:"machine_info"`
	}
	if err := decode(r, 2*ade.MaxMachineInfoBytes, &req); err != nil {
		return err
	}
	if _, err := s.liveTenant(r, key); err != nil {
		return err
	}
	res, err := s.ADE.VerifyMachineInfo(r.Context(), key, req.MachineInfo)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, res)
}

// --------------------------------------------------------- profile signing

func (s *Server) signProfile(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, signing.MaxProfile+1))
	if err != nil {
		return apierr.BadRequest("unreadable body")
	}
	if _, err := s.liveTenant(r, key); err != nil {
		return err
	}
	if err := signing.CheckProfile(body, s.Cfg.PublicBase, key); err != nil {
		return err
	}
	id, err := signing.Load(r.Context(), s.DB, s.Keys)
	if errors.Is(err, signing.ErrNoIdentity) {
		return apierr.Conflict("signing_identity_missing", "no profile signing identity is configured on this instance")
	}
	if err != nil {
		s.Logger.Error("msg", "signing identity", "component", "api", "err", err)
		return apierr.Conflict("signing_identity_unusable", "the profile signing identity is expired or unreadable")
	}
	signed, err := signing.Sign(id, body)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(signed)
	return err
}

// --------------------------------------------------------------------- ADE

func adeTokenID(r *http.Request) string { return strings.ToLower(r.PathValue("id")) }

func (s *Server) createADEToken(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	t, err := s.ADE.Create(r.Context(), key)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, t)
}

func (s *Server) listADETokens(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	if err := s.tenantExists(r, key); err != nil {
		return err
	}
	list, err := s.ADE.List(r.Context(), key)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"ade_tokens": list})
}

func (s *Server) getADEToken(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	t, err := s.ADE.Get(r.Context(), key, adeTokenID(r))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, t)
}

func (s *Server) uploadADEToken(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, ade.MaxTokenFile+1))
	if err != nil {
		return apierr.BadRequest("unreadable body")
	}
	if len(body) > ade.MaxTokenFile {
		return apierr.New(http.StatusRequestEntityTooLarge, "payload_too_large", "the token file is limited to 64 KiB")
	}
	if len(body) == 0 {
		return apierr.BadRequest("the body must be the .p7m file downloaded from Apple Business")
	}
	t, err := s.ADE.Upload(r.Context(), key, adeTokenID(r), body)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, t)
}

func (s *Server) deleteADEToken(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	if err := s.ADE.Delete(r.Context(), key, adeTokenID(r)); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"id": adeTokenID(r), "state": ade.StateRemoved})
}

func (s *Server) defineADEProfile(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req struct {
		Profile json.RawMessage `json:"profile"`
		Default bool            `json:"default"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	var profile map[string]any
	if err := json.Unmarshal(req.Profile, &profile); err != nil {
		return apierr.BadRequest("profile must be a JSON object")
	}
	res, err := s.ADE.DefineProfile(r.Context(), key, adeTokenID(r), r.PathValue("usage"), profile, req.Default)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, res)
}

func (s *Server) assignADEProfile(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req struct {
		Usage   string   `json:"usage"`
		Serials []string `json:"serials"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	res, err := s.ADE.Assign(r.Context(), key, adeTokenID(r), req.Usage, req.Serials)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, res)
}

func (s *Server) syncADEToken(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	if err := s.ADE.SyncNow(r.Context(), key, adeTokenID(r)); err != nil {
		return err
	}
	return writeJSON(w, http.StatusAccepted, map[string]any{"id": adeTokenID(r), "sync": "requested"})
}

func (s *Server) accountDrivenEnrollment(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	u, err := s.ADE.AccountDrivenEnrollment(r.Context(), key, adeTokenID(r))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"mdm_service_discovery_url": u})
}
