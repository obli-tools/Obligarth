package tenant

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/cryptoutil"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// PushImport is an imported push certificate and its private key (step 1:
// laboratory and migrations; step 2 generates the key inside apple-edge).
type PushImport struct {
	CertPEM          []byte
	KeyPEM           []byte
	AllowTopicChange bool
}

// ImportPushCert checks and activates a push certificate for tenant key:
// the key matches the certificate, the topic (subject UID) is free or
// already bound to this tenant, the certificate is valid now, and a renewal
// keeps the topic unless a change is explicitly allowed.
func (s *Service) ImportPushCert(ctx context.Context, key string, in PushImport) (PushCertInfo, error) {
	cert, err := firstCert(in.CertPEM)
	if err != nil {
		return PushCertInfo{}, apierr.Unprocessable("invalid_certificate", "cert_pem does not hold a certificate")
	}
	priv, err := parseKey(in.KeyPEM)
	if err != nil {
		return PushCertInfo{}, apierr.Unprocessable("invalid_key", "key_pem does not hold a supported private key")
	}
	if !publicKeysEqual(cert.PublicKey, priv) {
		return PushCertInfo{}, apierr.Unprocessable("key_mismatch", "the private key does not match the certificate")
	}
	topic, err := cryptoutil.TopicFromCert(cert)
	if err != nil || !strings.HasPrefix(topic, "com.apple.mgmt.") {
		return PushCertInfo{}, apierr.Unprocessable("invalid_topic", "the certificate carries no MDM push topic")
	}
	now := s.now()
	if !now.Before(cert.NotAfter) || now.Add(time.Hour).Before(cert.NotBefore) {
		return PushCertInfo{}, apierr.Unprocessable("certificate_not_valid_now", "the certificate is expired or not yet valid")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return PushCertInfo{}, err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	sum := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(sum[:])
	notAfter := cert.NotAfter.UTC()
	info := PushCertInfo{State: "active", Topic: topic, NotAfter: &notAfter}
	unchanged := false
	err = store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		st, err := s.state(ctx, tx, key, true)
		if err != nil {
			return err
		}
		if st != StateActive && st != StateSuspended {
			return errNotLive
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO apple_edge.topics (topic, tenant_key) VALUES ($1, $2) ON CONFLICT (topic) DO NOTHING`, topic, key); err != nil {
			return err
		}
		var owner string
		if err := tx.QueryRowContext(ctx, `SELECT tenant_key FROM apple_edge.topics WHERE topic = $1`, topic).Scan(&owner); err != nil {
			return err
		}
		if owner != key {
			return apierr.Conflict("topic_bound_to_other_tenant", "the push topic belongs to another tenant")
		}
		var activeID, activeTopic, activeCert sql.NullString
		err = tx.QueryRowContext(ctx, `SELECT id, topic, cert_pem FROM apple_edge.push_certs WHERE tenant_key = $1 AND state = 'active'`, key).Scan(&activeID, &activeTopic, &activeCert)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if activeID.Valid {
			if c, err := firstCert([]byte(activeCert.String)); err == nil && sha256.Sum256(c.Raw) == sum {
				unchanged = true
				info.ID = activeID.String
				return nil
			}
			if activeTopic.String != topic {
				if !in.AllowTopicChange {
					return apierr.Unprocessable("topic_change_not_allowed", "the renewal changes the push topic (allow_topic_change is not set)")
				}
				if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.push_certs SET state = 'legacy' WHERE id = $1`, activeID.String); err != nil {
					return err
				}
			} else if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.push_certs SET state = 'superseded' WHERE id = $1`, activeID.String); err != nil {
				return err
			}
		}
		// A legacy certificate of the same topic is replaced by the new one.
		if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.push_certs SET state = 'superseded' WHERE tenant_key = $1 AND topic = $2 AND state = 'legacy'`, key, topic); err != nil {
			return err
		}
		dek, err := s.Keys.ActiveDEK(ctx, tx, key)
		if err != nil {
			return err
		}
		info.ID = ids.NewUUID()
		enc, err := dek.Seal("apple_edge.push_certs", "key_enc", info.ID, key, keyDER)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.push_certs (id, tenant_key, state, topic, cert_pem, key_enc, not_after, stale_token, activated_at)
VALUES ($1, $2, 'active', $3, $4, $5, $6,
        coalesce((SELECT max(stale_token) FROM apple_edge.push_certs WHERE tenant_key = $2), 0) + 1, now())`,
			info.ID, key, topic, certPEM, enc, notAfter); err != nil {
			if store.IsUniqueViolation(err, "push_certs_topic_live") {
				return apierr.Conflict("topic_bound_to_other_tenant", "the push topic is in use")
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.tenants SET updated_at = now() WHERE key = $1`, key); err != nil {
			return err
		}
		if err := s.Out.Insert(ctx, tx, outbox.T(key, "apns.certificate_activated", map[string]any{
			"topic": topic, "not_after": notAfter.Format(time.RFC3339), "cert_sha256": fingerprint,
		})); err != nil {
			return err
		}
		return store.Notify(ctx, tx, Channel, key)
	})
	if store.IsUniqueViolation(err, "topics_pkey") {
		return PushCertInfo{}, apierr.Conflict("topic_bound_to_other_tenant", "the push topic belongs to another tenant")
	}
	if err != nil {
		return PushCertInfo{}, err
	}
	if !unchanged {
		s.Out.Committed()
		if err := s.Reg.Reload(ctx, key); err != nil {
			s.Logger.Error("msg", "registry reload after push certificate import", "tenant", key, "err", err)
		}
	}
	now2 := s.now().UTC()
	info.ActivatedAt = &now2
	return info, nil
}

func firstCert(b []byte) (*x509.Certificate, error) {
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, errors.New("no certificate")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

func parseKey(b []byte) (crypto.Signer, error) {
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, errors.New("no private key")
		}
		switch blk.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(blk.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			switch sk := k.(type) {
			case *rsa.PrivateKey:
				return sk, nil
			case *ecdsa.PrivateKey:
				return sk, nil
			}
			return nil, errors.New("unsupported key type")
		}
	}
}

func publicKeysEqual(pub any, priv crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := priv.Public().(equaler)
	return ok && e.Equal(pub)
}
