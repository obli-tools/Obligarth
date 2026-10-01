// Package scep serves SCEP for one tenant with the micromdm/scep library:
// the tenant CA (which also decrypts the PKCS#7 envelope), restricted
// capabilities, one-time challenges kept hashed in PostgreSQL, and a signer
// that imposes the certificate content instead of copying the CSR.
package scep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	kitlog "github.com/go-kit/kit/log"
	scepcrypto "github.com/micromdm/scep/v2/cryptoutil"
	scepserver "github.com/micromdm/scep/v2/server"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"

	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/reqctx"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// Capabilities announced by GetCACaps: no Renewal, SHA-1 or DES3.
const Capabilities = "POSTPKIOperation\nSHA-256\nAES\nSCEPStandard"

// MinDeviceKeyBits is the smallest RSA key accepted in a CSR.
const MinDeviceKeyBits = 2048

var aesOnce sync.Once

// useAES makes the CertRep envelope use AES-128-CBC (RFC 8894 "AES"):
// the pkcs7 library defaults to single DES for every encryption.
func useAES() {
	aesOnce.Do(func() { pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC })
}

// Config holds the dependencies shared by every tenant.
type Config struct {
	DB       *sql.DB
	Out      *outbox.Writer
	Logger   *obs.Logger
	Metrics  *obs.Metrics
	CertDays int
	Now      func() time.Time
}

// CA is the issuing CA of a tenant.
type CA struct {
	ID   string
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// NewHandler returns the SCEP HTTP handler of a tenant. It serves the path
// "/scep"; the device router rewrites /t/<key>/scep before calling it.
func NewHandler(cfg Config, tenant string, ca CA) (http.Handler, error) {
	useAES()
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	var kit kitlog.Logger = cfg.Logger.With("component", "scep", "tenant", tenant).Kit()
	s := &signer{cfg: cfg, tenant: tenant, ca: ca}
	inner, err := scepserver.NewService(ca.Cert, ca.Key, s, scepserver.WithLogger(kit))
	if err != nil {
		return nil, err
	}
	svc := restricted{inner}
	return scepserver.MakeHTTPHandler(scepserver.MakeServerEndpoints(svc), svc, kit), nil
}

// restricted narrows the upstream service: fixed capabilities and error
// messages that never reach the client.
type restricted struct{ scepserver.Service }

func (restricted) GetCACaps(context.Context) ([]byte, error) { return []byte(Capabilities), nil }

func (r restricted) PKIOperation(ctx context.Context, msg []byte) ([]byte, error) {
	out, err := r.Service.PKIOperation(ctx, msg)
	if err != nil {
		// The transport copies the error text into the body.
		return nil, errors.New(http.StatusText(http.StatusInternalServerError))
	}
	return out, nil
}

// Rejection reasons (metric label).
const (
	reasonUnknown   = "unknown_challenge"
	reasonExpired   = "expired_challenge"
	reasonKey       = "key"
	reasonSignature = "csr_signature"
	reasonInternal  = "internal"
)

type signer struct {
	cfg    Config
	tenant string
	ca     CA
}

var errRefused = errors.New("scep: request refused")

func (s *signer) reject(reason string) error {
	s.cfg.Metrics.SCEPRejected.Inc(s.tenant, reason)
	return errRefused
}

// SignCSRContext consumes the one-time challenge, checks the CSR and issues
// the device identity. Any failure answers a SCEP failure (badRequest).
func (s *signer) SignCSRContext(ctx context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
	if m == nil || m.CSR == nil {
		return nil, s.reject(reasonUnknown)
	}
	sum := sha256.Sum256([]byte(m.ChallengePassword))
	tx, err := s.cfg.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, s.fail(err)
	}
	defer tx.Rollback()
	var ch struct {
		id         string
		sessionRef sql.NullString
		expires    time.Time
	}
	// One-time: consumed even if expired or if the CSR is refused below.
	err = tx.QueryRowContext(ctx, `
UPDATE apple_edge.scep_challenges SET used_at = now()
 WHERE tenant_key = $1 AND hash = $2 AND used_at IS NULL
RETURNING id, session_ref, expires_at`, s.tenant, sum[:]).Scan(&ch.id, &ch.sessionRef, &ch.expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, s.reject(reasonUnknown)
	}
	if err != nil {
		return nil, s.fail(err)
	}
	now := s.cfg.Now()
	reason := ""
	switch {
	case !now.Before(ch.expires):
		reason = reasonExpired
	case m.CSR.CheckSignature() != nil:
		reason = reasonSignature
	default:
		if pub, ok := m.CSR.PublicKey.(*rsa.PublicKey); !ok || pub.N.BitLen() < MinDeviceKeyBits {
			reason = reasonKey
		}
	}
	if reason != "" {
		if err := tx.Commit(); err != nil {
			return nil, s.fail(err)
		}
		return nil, s.reject(reason)
	}
	cert, err := s.issue(m.CSR.PublicKey, now)
	if err != nil {
		return nil, s.fail(err)
	}
	fp := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(fp[:])
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	if _, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.issued_certs (sha256, tenant_key, ca_id, serial_hex, challenge_id, not_after)
VALUES ($1, $2, $3, $4, $5, $6)`, fingerprint, s.tenant, s.ca.ID, serial, ch.id, cert.NotAfter.UTC()); err != nil {
		return nil, s.fail(err)
	}
	ev := outbox.T(s.tenant, "scep.certificate_issued", map[string]any{
		"challenge_id": ch.id, "session_ref": nullable(ch.sessionRef), "cert_sha256": fingerprint,
		"serial_hex": serial, "not_after": cert.NotAfter.UTC().Format(time.RFC3339),
	})
	if err := s.cfg.Out.Insert(ctx, tx, ev); err != nil {
		return nil, s.fail(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, s.fail(err)
	}
	s.cfg.Out.Committed()
	s.cfg.Logger.Info("msg", "device certificate issued", "component", "scep", "tenant", s.tenant, "request_id", reqctx.RequestID(ctx))
	return cert, nil
}

func (s *signer) fail(err error) error {
	s.cfg.Logger.Error("msg", "scep signer", "component", "scep", "tenant", s.tenant, "err", err)
	s.cfg.Metrics.SCEPRejected.Inc(s.tenant, reasonInternal)
	return errRefused
}

// issue builds the device certificate: the subject, key usages and
// validity are imposed; nothing is copied from the CSR but the public key.
func (s *signer) issue(pub any, now time.Time) (*x509.Certificate, error) {
	serial, err := RandomSerial()
	if err != nil {
		return nil, err
	}
	skid, err := scepcrypto.GenerateSubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         ids.NewUUID(),
			OrganizationalUnit: []string{s.tenant},
			Organization:       []string{"Obligarth"},
		},
		NotBefore:          now.Add(-5 * time.Minute).UTC(),
		NotAfter:           now.AddDate(0, 0, s.cfg.CertDays).UTC(),
		SubjectKeyId:       skid,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca.Cert, pub, s.ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// RandomSerial returns a random positive 128-bit serial number.
func RandomSerial() (*big.Int, error) {
	for {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

func nullable(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}

// Challenge limits.
const (
	ChallengeMinTTL     = 60 * time.Second
	ChallengeMaxTTL     = 3600 * time.Second
	ChallengeDefaultTTL = 900 * time.Second
)

// ChallengeRequest describes a challenge to create.
type ChallengeRequest struct {
	SessionRef    string
	TTL           time.Duration
	BindUDID      string
	BindSerial    string
	MachineInfoID string // verified MachineInfo the bindings come from
}

// NewChallenge stores a one-time challenge (hashed) and returns it in clear.
func NewChallenge(ctx context.Context, q store.Querier, tenant string, req ChallengeRequest) (challenge, id string, expires time.Time, err error) {
	if req.TTL == 0 {
		req.TTL = ChallengeDefaultTTL
	}
	if req.TTL < ChallengeMinTTL || req.TTL > ChallengeMaxTTL {
		return "", "", time.Time{}, fmt.Errorf("scep: ttl must be between %s and %s", ChallengeMinTTL, ChallengeMaxTTL)
	}
	challenge = ids.RandomString(24)
	sum := sha256.Sum256([]byte(challenge))
	id = ids.NewUUID()
	err = q.QueryRowContext(ctx, `
INSERT INTO apple_edge.scep_challenges (id, tenant_key, hash, session_ref, bind_udid, bind_serial, machine_info_id, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))
RETURNING expires_at`, id, tenant, sum[:], nullIf(req.SessionRef), nullIf(req.BindUDID), nullIf(req.BindSerial), nullIf(req.MachineInfoID), req.TTL.Seconds()).Scan(&expires)
	return challenge, id, expires, err
}

// PurgeChallenges deletes challenges used or expired for more than a day
// that no issued certificate refers to.
func PurgeChallenges(ctx context.Context, db *sql.DB) (int64, bool, error) {
	var n int64
	ran := false
	err := store.InTx(ctx, db, func(tx *sql.Tx) error {
		ok, err := store.TryXactLock(ctx, tx, "challenge-purge")
		if err != nil || !ok {
			return err
		}
		ran = true
		res, err := tx.ExecContext(ctx, `
DELETE FROM apple_edge.scep_challenges c
 WHERE coalesce(c.used_at, c.expires_at) < now() - interval '24 hours'
   AND NOT EXISTS (SELECT 1 FROM apple_edge.issued_certs i WHERE i.challenge_id = c.id)`)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, ran, err
}

func nullIf(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
