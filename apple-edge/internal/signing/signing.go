// Package signing signs enrollment profiles with the identity of the
// instance: CMS SignedData (SHA-256, certificate chain included) produced
// by smallstep/pkcs7. The identity is imported by an operations command and
// kept encrypted (instance DEK) in apple_edge.instance_secrets.
package signing

import (
	"bytes"
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
	"fmt"
	"strings"
	"time"

	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// Name is the instance_secrets row of the signing identity.
const Name = "profile_signing_identity"

// MaxProfile is the largest unsigned profile accepted.
const MaxProfile = 1 << 20

// ErrNoIdentity is returned when no signing identity was imported.
var ErrNoIdentity = errors.New("signing: no profile signing identity")

// Identity is a signing certificate (leaf first, then its chain) and its key.
type Identity struct {
	Chain []*x509.Certificate
	Key   crypto.Signer
}

// ParseIdentity reads a PEM certificate chain (leaf first) and a PEM private key.
func ParseIdentity(chainPEM, keyPEM []byte, now time.Time) (*Identity, error) {
	var chain []*x509.Certificate
	rest := chainPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signing: certificate: %w", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, errors.New("signing: no certificate in the chain file")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := key.Public().(equaler); !ok || !e.Equal(chain[0].PublicKey) {
		return nil, errors.New("signing: the key does not match the first certificate")
	}
	if now.After(chain[0].NotAfter) || now.Before(chain[0].NotBefore) {
		return nil, errors.New("signing: the certificate is not valid now")
	}
	for i := 1; i < len(chain); i++ {
		if chain[i-1].CheckSignatureFrom(chain[i]) != nil {
			return nil, fmt.Errorf("signing: certificate %d is not signed by certificate %d", i, i+1)
		}
	}
	return &Identity{Chain: chain, Key: key}, nil
}

func parseKey(b []byte) (crypto.Signer, error) {
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, errors.New("signing: no private key")
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
			return nil, errors.New("signing: unsupported key type")
		}
	}
}

// Import stores the identity, the key encrypted with the instance DEK.
func Import(ctx context.Context, db *sql.DB, keys *store.Keyring, id *Identity) error {
	der, err := x509.MarshalPKCS8PrivateKey(id.Key)
	if err != nil {
		return err
	}
	var chain bytes.Buffer
	for _, c := range id.Chain {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return store.InTx(ctx, db, func(tx *sql.Tx) error {
		dek, err := keys.ActiveDEK(ctx, tx, "")
		if err != nil {
			return err
		}
		enc, err := dek.Seal("apple_edge.instance_secrets", "value_enc", Name, "", der)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO apple_edge.instance_secrets (name, value_enc, cert_pem, not_after, updated_at) VALUES ($1, $2, $3, $4, now())
ON CONFLICT (name) DO UPDATE SET value_enc = EXCLUDED.value_enc, cert_pem = EXCLUDED.cert_pem,
    not_after = EXCLUDED.not_after, updated_at = now()`, Name, enc, chain.String(), id.Chain[0].NotAfter.UTC())
		return err
	})
}

// Info is the public description of the profile signing identity: the
// SHA-256 of its leaf certificate (DER, lower-case hexadecimal) and its
// expiry. It holds no secret.
type Info struct {
	SHA256   string    `json:"sha256"`
	NotAfter time.Time `json:"not_after"`
}

// Describe returns the public description of the signing identity, or nil
// when none was imported. The key is never opened.
func Describe(ctx context.Context, q store.Querier) (*Info, error) {
	var chainPEM sql.NullString
	var notAfter sql.NullTime
	err := q.QueryRowContext(ctx, `SELECT cert_pem, not_after FROM apple_edge.instance_secrets WHERE name = $1`, Name).Scan(&chainPEM, &notAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	info := &Info{}
	rest := []byte(chainPEM.String)
	for {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		sum := sha256.Sum256(blk.Bytes)
		info.SHA256 = hex.EncodeToString(sum[:])
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			info.NotAfter = c.NotAfter.UTC()
		}
		break
	}
	if notAfter.Valid {
		info.NotAfter = notAfter.Time.UTC()
	}
	return info, nil
}

// Load reads and decrypts the identity.
func Load(ctx context.Context, db *sql.DB, keys *store.Keyring) (*Identity, error) {
	var enc string
	var chainPEM sql.NullString
	err := db.QueryRowContext(ctx, `SELECT value_enc, cert_pem FROM apple_edge.instance_secrets WHERE name = $1`, Name).Scan(&enc, &chainPEM)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, err
	}
	der, err := keys.Open(ctx, db, "", "apple_edge.instance_secrets", "value_enc", Name, enc)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return ParseIdentity([]byte(chainPEM.String), keyPEM, time.Now())
}

// Sign returns the DER CMS SignedData of content (SHA-256, chain included).
func Sign(id *Identity, content []byte) ([]byte, error) {
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, err
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSignerChain(id.Chain[0], id.Key, id.Chain[1:], pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	return sd.Finish()
}

// CheckProfile verifies that content is an unsigned configuration profile
// whose MDM and SCEP payloads point to the tenant only (defence in depth:
// a profile of one tenant can never be signed for another tenant's URLs).
func CheckProfile(content []byte, publicBase, tenant string) error {
	if len(content) == 0 || len(content) > MaxProfile {
		return apierr.New(413, "payload_too_large", "the profile must hold 1 byte to 1 MiB")
	}
	var p struct {
		PayloadType    string
		PayloadContent []map[string]any
	}
	if err := plist.Unmarshal(content, &p); err != nil || p.PayloadType != "Configuration" {
		return apierr.Unprocessable("validation_failed", "the body must be an unsigned configuration profile (plist)")
	}
	prefix := strings.TrimRight(publicBase, "/") + "/t/" + tenant + "/"
	for _, pl := range p.PayloadContent {
		typ, _ := pl["PayloadType"].(string)
		var urls []string
		switch typ {
		case "com.apple.mdm":
			for _, k := range []string{"ServerURL", "CheckInURL"} {
				if v, ok := pl[k].(string); ok {
					urls = append(urls, v)
				} else if k == "ServerURL" {
					return apierr.Unprocessable("validation_failed", "the MDM payload has no ServerURL")
				}
			}
		case "com.apple.security.scep":
			if c, ok := pl["PayloadContent"].(map[string]any); ok {
				if v, ok := c["URL"].(string); ok {
					urls = append(urls, v)
				}
			}
		}
		for _, u := range urls {
			if !strings.HasPrefix(u, prefix) || strings.Contains(u, "/../") || strings.Contains(u, "\\") {
				return apierr.Unprocessable("url_outside_tenant", "the profile points to URLs outside this tenant")
			}
		}
	}
	return nil
}
