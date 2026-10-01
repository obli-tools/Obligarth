// Package ade runs Automated Device Enrollment for each tenant with
// NanoDEP as a library: server tokens (key pair, encrypted .p7m secrets),
// a synchronisation loop per token whose cursor is written in the same
// transaction as its events, ADE profiles and their assignment by usage,
// the account-driven enrollment discovery URL, and the verification of the
// MachineInfo signed by Apple that proves an ADE device belongs to a tenant.
package ade

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"sync"
	"time"

	depclient "github.com/micromdm/nanodep/client"
	"github.com/micromdm/nanodep/godep"
	"github.com/micromdm/nanodep/tokenpki"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// Channel is the NOTIFY channel of ADE tokens (payload: token id): the
// replica that runs the loop of the token synchronises at once.
const Channel = "apple_edge_ade"

const tokensTable = "apple_edge.ade_tokens"

// Token states.
const (
	StateAwaiting = "awaiting_token"
	StateActive   = "active"
	StateTerms    = "terms_not_signed"
	StateExpired  = "expired"
	StateError    = "error"
	StateRemoved  = "removed"
)

// Limits.
const (
	MaxTokenFile    = 64 << 10
	MaxTokens       = 50
	keyPairValidity = 365
)

// Service implements the ADE operations of the internal API.
type Service struct {
	DB         *sql.DB
	Keys       *store.Keyring
	Out        *outbox.Writer
	Logger     *obs.Logger
	Metrics    *obs.Metrics
	PublicBase string
	BaseURL    string
	UserAgent  string
	HTTP       *http.Client
	Roots      []*x509.Certificate // MachineInfo roots
	Now        func() time.Time

	clientOnce sync.Once
	client     *godep.Client
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Client returns the ADE API client of stored tokens (one session per token).
func (s *Service) Client() *godep.Client {
	s.clientOnce.Do(func() { s.client = s.newClient(tokenStore{s}) })
	return s.client
}

// TokenInfo describes an ADE token (never a secret).
type TokenInfo struct {
	ID                string     `json:"id"`
	State             string     `json:"state"`
	CertificatePEM    string     `json:"certificate_pem"`
	ServerName        *string    `json:"server_name"`
	ServerUUID        *string    `json:"server_uuid"`
	NotAfter          *time.Time `json:"not_after"`
	LastSyncAt        *time.Time `json:"last_sync_at"`
	LastFetchAt       *time.Time `json:"last_fetch_at"`
	ConsecutiveErrors int        `json:"consecutive_errors"`
	LastError         *string    `json:"last_error"`
	CreatedAt         time.Time  `json:"created_at"`
	Devices           *int       `json:"devices,omitempty"`
	Profiles          []Profile  `json:"profiles,omitempty"`
}

// Profile describes a defined ADE profile.
type Profile struct {
	Usage       string     `json:"usage"`
	ProfileUUID *string    `json:"profile_uuid"`
	IsDefault   bool       `json:"is_default"`
	DefinedAt   *time.Time `json:"defined_at"`
}

const tokenCols = `id, state, tokenpki_cert_pem, server_name, server_uuid, token_not_after, last_sync_at, last_fetch_at, consecutive_errors, last_error, created_at`

func scanToken(sc interface{ Scan(...any) error }) (TokenInfo, error) {
	var t TokenInfo
	var na, ls, lf sql.NullTime
	err := sc.Scan(&t.ID, &t.State, &t.CertificatePEM, &t.ServerName, &t.ServerUUID, &na, &ls, &lf, &t.ConsecutiveErrors, &t.LastError, &t.CreatedAt)
	for _, x := range []struct {
		src sql.NullTime
		dst **time.Time
	}{{na, &t.NotAfter}, {ls, &t.LastSyncAt}, {lf, &t.LastFetchAt}} {
		if x.src.Valid {
			v := x.src.Time.UTC()
			*x.dst = &v
		}
	}
	t.CreatedAt = t.CreatedAt.UTC()
	return t, err
}

var errTokenNotFound = apierr.NotFound("ade_token_not_found", "ADE token not found")

func liveTenant(ctx context.Context, q store.Querier, tenant string, forUpdate bool) error {
	var st string
	query := `SELECT state FROM apple_edge.tenants WHERE key = $1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	err := q.QueryRowContext(ctx, query, tenant).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return apierr.TenantNotFound
	}
	if err != nil {
		return err
	}
	if st != "active" && st != "suspended" {
		return apierr.Conflict("tenant_not_live", "the tenant is retiring or retired")
	}
	return nil
}

// Create generates the key pair of a new token; the administrator uploads
// the public certificate to Apple Business and downloads the .p7m.
func (s *Service) Create(ctx context.Context, tenant string) (TokenInfo, error) {
	if err := liveTenant(ctx, s.DB, tenant, false); err != nil {
		return TokenInfo{}, err
	}
	key, cert, err := tokenpki.SelfSignedRSAKeypair("obligarth-apple-edge", keyPairValidity)
	if err != nil {
		return TokenInfo{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return TokenInfo{}, err
	}
	id := ids.NewUUID()
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	var out TokenInfo
	err = store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		if err := liveTenant(ctx, tx, tenant, true); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM apple_edge.ade_tokens WHERE tenant_key = $1 AND state <> 'removed'`, tenant).Scan(&n); err != nil {
			return err
		}
		if n >= MaxTokens {
			return apierr.Conflict("too_many_ade_tokens", "too many ADE tokens for this tenant")
		}
		dek, err := s.Keys.ActiveDEK(ctx, tx, tenant)
		if err != nil {
			return err
		}
		enc, err := dek.Seal(tokensTable, "tokenpki_key_enc", id, tenant, keyDER)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.ade_tokens (id, tenant_key, state, tokenpki_cert_pem, tokenpki_key_enc) VALUES ($1, $2, 'awaiting_token', $3, $4)`,
			id, tenant, certPEM, enc); err != nil {
			return err
		}
		// Non-secret upstream state (cursor) lives in NanoDEP's table.
		if _, err := tx.ExecContext(ctx, `INSERT INTO nanodep.dep_names (name) VALUES ($1)`, id); err != nil {
			return err
		}
		out, err = scanToken(tx.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM apple_edge.ade_tokens WHERE id = $1`, id))
		return err
	})
	return out, err
}

// tokenRow loads a token of the tenant.
func (s *Service) tokenRow(ctx context.Context, q store.Querier, tenant, id string, forUpdate bool) (TokenInfo, error) {
	if !ids.ValidUUID(id) {
		return TokenInfo{}, errTokenNotFound
	}
	query := `SELECT ` + tokenCols + ` FROM apple_edge.ade_tokens WHERE id = $1 AND tenant_key = $2`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	t, err := scanToken(q.QueryRowContext(ctx, query, id, tenant))
	if errors.Is(err, sql.ErrNoRows) {
		return t, errTokenNotFound
	}
	return t, err
}

// Upload decrypts the .p7m downloaded from Apple Business with the token's
// key, checks the OAuth secrets with Apple (GET /account) and activates the
// token. The same call renews a token.
func (s *Service) Upload(ctx context.Context, tenant, id string, p7m []byte) (TokenInfo, error) {
	if err := liveTenant(ctx, s.DB, tenant, false); err != nil {
		return TokenInfo{}, err
	}
	t, err := s.tokenRow(ctx, s.DB, tenant, id, false)
	if err != nil {
		return t, err
	}
	if t.State == StateRemoved {
		return t, apierr.Conflict("ade_token_removed", "the ADE token was removed")
	}
	var keyEnc string
	if err := s.DB.QueryRowContext(ctx, `SELECT tokenpki_key_enc FROM apple_edge.ade_tokens WHERE id = $1`, id).Scan(&keyEnc); err != nil {
		return t, err
	}
	der, err := s.Keys.Open(ctx, s.DB, tenant, tokensTable, "tokenpki_key_enc", id, keyEnc)
	if err != nil {
		return t, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return t, err
	}
	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return t, errors.New("ade: token key is not RSA")
	}
	blk, _ := pem.Decode([]byte(t.CertificatePEM))
	if blk == nil {
		return t, errors.New("ade: token certificate unreadable")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return t, err
	}
	invalid := apierr.Unprocessable("invalid_token_file", "the file is not a server token encrypted for this ADE token")
	plain, err := tokenpki.DecryptTokenJSON(p7m, cert, priv)
	if err != nil {
		return t, invalid
	}
	var oauth depclient.OAuth1Tokens
	if err := json.Unmarshal(plain, &oauth); err != nil || !oauth.Valid() {
		return t, invalid
	}
	if !oauth.AccessTokenExpiry.IsZero() && !s.now().Before(oauth.AccessTokenExpiry) {
		return t, apierr.Unprocessable("ade_token_expired", "the server token is expired")
	}
	state, code := StateActive, ""
	acct, err := s.newClient(staticStore{tokens: &oauth, base: s.BaseURL}).AccountDetail(ctx, id)
	if err != nil {
		kind, c := Classify(err)
		switch kind {
		case KindTerms:
			state, code = StateTerms, c
		case KindTransient:
			s.Logger.Info("msg", "ADE account check", "component", "ade", "tenant", tenant, "ade_token", id, "err", err)
			return t, apierr.New(http.StatusBadGateway, "ade_unavailable", "the ADE API did not answer, try again")
		default:
			return t, apierr.Unprocessable("ade_token_rejected", "Apple refused the server token ("+c+")")
		}
	}
	secrets, err := json.Marshal(oauth)
	if err != nil {
		return t, err
	}
	var notAfter any
	if !oauth.AccessTokenExpiry.IsZero() {
		notAfter = oauth.AccessTokenExpiry.UTC()
	}
	var serverName, serverUUID any
	if acct != nil {
		if acct.ServerName != nil {
			serverName = *acct.ServerName
		}
		if acct.ServerUUID != nil {
			serverUUID = *acct.ServerUUID
		}
	}
	err = store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		cur, err := s.tokenRow(ctx, tx, tenant, id, true)
		if err != nil {
			return err
		}
		if cur.State == StateRemoved {
			return apierr.Conflict("ade_token_removed", "the ADE token was removed")
		}
		dek, err := s.Keys.ActiveDEK(ctx, tx, tenant)
		if err != nil {
			return err
		}
		enc, err := dek.Seal(tokensTable, "oauth_enc", id, tenant, secrets)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE apple_edge.ade_tokens
   SET state = $3, oauth_enc = $4, token_not_after = $5, server_name = coalesce($6, server_name),
       server_uuid = coalesce($7, server_uuid), consecutive_errors = 0, last_error = $8, updated_at = now()
 WHERE id = $1 AND tenant_key = $2`, id, tenant, state, enc, notAfter, serverName, serverUUID, nullIf(code)); err != nil {
			return err
		}
		// A renewed token has a new expiry: its alerts start over.
		if _, err := tx.ExecContext(ctx, `DELETE FROM apple_edge.expiry_alerts WHERE subject = $1`, "ade_token:"+id); err != nil {
			return err
		}
		ev := outbox.T(tenant, "ade.token_activated", map[string]any{"token_id": id, "server_name": serverName, "server_uuid": serverUUID, "not_after": notAfter})
		if state == StateTerms {
			ev = outbox.T(tenant, "ade.terms_not_signed", map[string]any{"token_id": id, "code": code})
		}
		if err := s.Out.Insert(ctx, tx, ev); err != nil {
			return err
		}
		if err := store.Notify(ctx, tx, Channel, id); err != nil {
			return err
		}
		t, err = s.tokenRow(ctx, tx, tenant, id, false)
		return err
	})
	if err != nil {
		return t, err
	}
	s.Out.Committed()
	if s.Metrics != nil && t.NotAfter != nil {
		s.Metrics.ADETokenExpiry.Set(float64(t.NotAfter.Unix()), tenant, id)
	}
	return t, nil
}

// List returns the tokens of a tenant.
func (s *Service) List(ctx context.Context, tenant string) ([]TokenInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+tokenCols+` FROM apple_edge.ade_tokens WHERE tenant_key = $1 ORDER BY created_at`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TokenInfo{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Get returns a token with its device count and profiles.
func (s *Service) Get(ctx context.Context, tenant, id string) (TokenInfo, error) {
	t, err := s.tokenRow(ctx, s.DB, tenant, id, false)
	if err != nil {
		return t, err
	}
	var n int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM apple_edge.ade_devices WHERE token_id = $1`, id).Scan(&n); err != nil {
		return t, err
	}
	t.Devices = &n
	rows, err := s.DB.QueryContext(ctx, `SELECT usage, profile_uuid, is_default, defined_at FROM apple_edge.ade_profiles WHERE token_id = $1 ORDER BY usage`, id)
	if err != nil {
		return t, err
	}
	defer rows.Close()
	t.Profiles = []Profile{}
	for rows.Next() {
		var p Profile
		var at sql.NullTime
		if err := rows.Scan(&p.Usage, &p.ProfileUUID, &p.IsDefault, &at); err != nil {
			return t, err
		}
		if at.Valid {
			v := at.Time.UTC()
			p.DefinedAt = &v
		}
		t.Profiles = append(t.Profiles, p)
	}
	return t, rows.Err()
}

// Delete removes a token: its secrets are destroyed, its devices and
// profiles forgotten, its loop stopped.
func (s *Service) Delete(ctx context.Context, tenant, id string) error {
	err := store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		t, err := s.tokenRow(ctx, tx, tenant, id, true)
		if err != nil {
			return err
		}
		if t.State == StateRemoved {
			return nil
		}
		for _, q := range []string{
			`DELETE FROM apple_edge.ade_devices WHERE token_id = $1`,
			`DELETE FROM apple_edge.ade_profiles WHERE token_id = $1`,
			`DELETE FROM nanodep.dep_names WHERE name = $1::text`,
			`DELETE FROM apple_edge.expiry_alerts WHERE subject = 'ade_token:' || $1::text`,
			`UPDATE apple_edge.ade_tokens SET state = 'removed', tokenpki_key_enc = NULL, oauth_enc = NULL, updated_at = now() WHERE id = $1`,
		} {
			if _, err := tx.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
		return store.Notify(ctx, tx, Channel, id)
	})
	if err == nil && s.Metrics != nil {
		s.Metrics.ADETokenExpiry.Set(0, tenant, id)
	}
	return err
}

// SyncNow asks the replica that runs the token's loop to synchronise.
func (s *Service) SyncNow(ctx context.Context, tenant, id string) error {
	t, err := s.tokenRow(ctx, s.DB, tenant, id, false)
	if err != nil {
		return err
	}
	if t.State != StateActive && t.State != StateTerms {
		return apierr.Conflict("ade_token_not_active", "the ADE token is not active")
	}
	return store.Notify(ctx, s.DB, Channel, id)
}

func nullIf(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
