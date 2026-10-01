package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage/pgsql"
	"github.com/micromdm/plist"

	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
)

// NanoStore wraps NanoMDM's PostgreSQL storage so that protocol secrets
// never reach the upstream tables: the UnlockToken is removed from the
// TokenUpdate (message and raw plist, re-serialised in canonical form) and
// kept encrypted in apple_edge.device_secrets; bootstrap tokens live there
// entirely.
type NanoStore struct {
	*pgsql.PgSQLStorage
	secrets *Secrets
}

// NewNanoStore wraps upstream with the secret store.
func NewNanoStore(upstream *pgsql.PgSQLStorage, secrets *Secrets) *NanoStore {
	return &NanoStore{PgSQLStorage: upstream, secrets: secrets}
}

func tenantOf(r *mdm.Request) (string, error) {
	if r.EnrollID == nil {
		return "", errors.New("store: request without enrollment id")
	}
	id := r.ID
	if r.ParentID != "" {
		id = r.ParentID
	}
	key, _, ok := ids.SplitNamespaced(id)
	if !ok {
		return "", errors.New("store: enrollment id is not namespaced")
	}
	return key, nil
}

// StoreAuthenticate mirrors the upstream reset of the bootstrap token on
// re-enrollment, then delegates.
func (s *NanoStore) StoreAuthenticate(r *mdm.Request, msg *mdm.Authenticate) error {
	if err := s.secrets.Supersede(r.Context(), s.secrets.db, r.ID, SecretBootstrapToken); err != nil {
		return err
	}
	return s.PgSQLStorage.StoreAuthenticate(r, msg)
}

// StoreTokenUpdate extracts the UnlockToken (device channel) into the
// secret store and hands a stripped, re-serialised copy to upstream.
func (s *NanoStore) StoreTokenUpdate(r *mdm.Request, msg *mdm.TokenUpdate) error {
	stripped, err := StripTokenUpdate(msg)
	if err != nil {
		return err
	}
	if len(msg.UnlockToken) > 0 && r.ParentID == "" {
		tenant, err := tenantOf(r)
		if err != nil {
			return err
		}
		if _, err := s.secrets.Put(r.Context(), tenant, r.ID, SecretUnlockToken, msg.UnlockToken); err != nil {
			return fmt.Errorf("store: unlock token: %w", err)
		}
	}
	return s.PgSQLStorage.StoreTokenUpdate(r, stripped)
}

// StripTokenUpdate returns a copy of msg without UnlockToken, whose Raw is
// the original plist minus the UnlockToken key, re-serialised by apple-edge
// (canonical form, whatever the device's encoding of the key).
func StripTokenUpdate(msg *mdm.TokenUpdate) (*mdm.TokenUpdate, error) {
	var m map[string]interface{}
	if err := plist.Unmarshal(msg.Raw, &m); err != nil {
		return nil, fmt.Errorf("store: re-reading TokenUpdate: %w", err)
	}
	delete(m, "UnlockToken")
	raw, err := plist.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: re-serialising TokenUpdate: %w", err)
	}
	c := *msg
	c.UnlockToken = nil
	c.Raw = raw
	return &c, nil
}

// StoreBootstrapToken keeps the token encrypted in apple_edge only.
func (s *NanoStore) StoreBootstrapToken(r *mdm.Request, msg *mdm.SetBootstrapToken) error {
	tenant, err := tenantOf(r)
	if err != nil {
		return err
	}
	if len(msg.BootstrapToken.BootstrapToken) == 0 {
		return s.secrets.Supersede(r.Context(), s.secrets.db, r.ID, SecretBootstrapToken)
	}
	_, err = s.secrets.Put(r.Context(), tenant, r.ID, SecretBootstrapToken, msg.BootstrapToken.BootstrapToken)
	return err
}

// RetrieveBootstrapToken reads the token from apple_edge.
func (s *NanoStore) RetrieveBootstrapToken(r *mdm.Request, _ *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	tenant, err := tenantOf(r)
	if err != nil {
		return nil, err
	}
	_, v, err := s.secrets.Current(r.Context(), tenant, r.ID, SecretBootstrapToken)
	if errors.Is(err, ErrSecretNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &mdm.BootstrapToken{BootstrapToken: v}, nil
}

// DisableEnrollment disables a device enrollment (and its user channels)
// and deactivates its queue, with the upstream semantics of Authenticate.
func (s *NanoStore) DisableEnrollment(ctx context.Context, deviceID string) error {
	req := mdm.NewRequestWithContext(ctx, nil)
	req.EnrollID = &mdm.EnrollID{ID: deviceID, Type: mdm.Device}
	if err := s.ClearQueue(req); err != nil {
		return err
	}
	return s.Disable(req)
}
