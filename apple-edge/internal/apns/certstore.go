// Package apns sends the MDM pushes of apple-edge: a push certificate
// store over apple_edge.push_certs (keys decrypted on demand), an HTTP/2
// provider per certificate (headers, typed APNs errors, circuit breaker),
// and a scheduler that applies the rate limits, the fairness between
// tenants, the coalescing per enrollment and the reactions to APNs answers.
// The upstream push service keeps the selection by topic, the provider
// cache and the stale-token check.
package apns

import (
	"context"
	"database/sql"
	"encoding/pem"
	"errors"
	"strconv"
	"time"

	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// ErrDisabled means that a topic has no usable push certificate: none,
// expired, revoked, or its tenant is not active. Pushes answer "disabled"
// instead of meeting a 403 at APNs.
var ErrDisabled = errors.New("apns: no usable push certificate")

// CertStore implements NanoMDM's storage.PushCertStore on
// apple_edge.push_certs.
type CertStore struct {
	DB   *sql.DB
	Keys *store.Keyring
	Now  func() time.Time
}

func (s *CertStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

const liveCertQuery = `
SELECT p.id, p.tenant_key, p.cert_pem, p.key_enc, p.not_after, p.stale_token
  FROM apple_edge.push_certs p JOIN apple_edge.tenants t ON t.key = p.tenant_key
 WHERE p.topic = $1 AND p.state IN ('active', 'legacy') AND t.state = 'active'`

type liveCert struct {
	id, tenant, certPEM, keyEnc string
	notAfter                    time.Time
	stale                       int64
}

func (s *CertStore) live(ctx context.Context, topic string) (*liveCert, error) {
	var c liveCert
	var notAfter sql.NullTime
	var certPEM sql.NullString
	err := s.DB.QueryRowContext(ctx, liveCertQuery, topic).Scan(&c.id, &c.tenant, &certPEM, &c.keyEnc, &notAfter, &c.stale)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDisabled
	}
	if err != nil {
		return nil, err
	}
	if !certPEM.Valid || !notAfter.Valid || !s.now().Before(notAfter.Time) {
		return nil, ErrDisabled
	}
	c.certPEM, c.notAfter = certPEM.String, notAfter.Time
	return &c, nil
}

func staleToken(id string, n int64) string { return id + "/" + strconv.FormatInt(n, 10) }

// RetrievePushCert returns the live certificate of topic and its key.
func (s *CertStore) RetrievePushCert(ctx context.Context, topic string) (pemCert, pemKey []byte, token string, err error) {
	c, err := s.live(ctx, topic)
	if err != nil {
		return nil, nil, "", err
	}
	der, err := s.Keys.Open(ctx, s.DB, c.tenant, "apple_edge.push_certs", "key_enc", c.id, c.keyEnc)
	if err != nil {
		return nil, nil, "", err
	}
	return []byte(c.certPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), staleToken(c.id, c.stale), nil
}

// IsPushCertStale reports whether the certificate of topic changed (or
// expired) since token was issued.
func (s *CertStore) IsPushCertStale(ctx context.Context, topic, token string) (bool, error) {
	c, err := s.live(ctx, topic)
	if errors.Is(err, ErrDisabled) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return staleToken(c.id, c.stale) != token, nil
}
