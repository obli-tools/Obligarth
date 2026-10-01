// Package envelope implements the envelope encryption shared with the
// Node brain: a KEK per service wraps one DEK per tenant (plus one for the
// instance), and every secret column holds
//
//	v1:<kid>:<iv>:<ct>:<tag>
//
// where iv, ct and tag are base64url without padding, the cipher is
// AES-256-GCM (96-bit IV, 128-bit tag) and kid is the DEK id (or the KEK
// id for a wrapped DEK). The AAD binds a ciphertext to its schema, table,
// column, row and tenant, so that it cannot be copied elsewhere.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	version  = "v1"
	keySize  = 32
	ivSize   = 12
	tagSize  = 16
	noTenant = "-"
)

var (
	// ErrFormat is returned for a malformed ciphertext.
	ErrFormat = errors.New("envelope: malformed ciphertext")
	// ErrDecrypt is returned when authentication fails (wrong key, AAD or data).
	ErrDecrypt = errors.New("envelope: decryption failed")
	// ErrKeyID is returned when the ciphertext was sealed with another key.
	ErrKeyID = errors.New("envelope: key id mismatch")

	b64 = base64.RawURLEncoding
)

// AAD returns the additional data of a secret column:
// "<schema>.<table>:<column>:<primary key>:<tenant key or ->".
func AAD(schemaTable, column, pk, tenant string) []byte {
	if tenant == "" {
		tenant = noTenant
	}
	return []byte(schemaTable + ":" + column + ":" + pk + ":" + tenant)
}

// Seal encrypts plaintext with key (32 bytes) under kid and aad.
func Seal(key []byte, kid string, aad, plaintext []byte) (string, error) {
	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	return sealWithIV(key, kid, iv, aad, plaintext)
}

func sealWithIV(key []byte, kid string, iv, aad, plaintext []byte) (string, error) {
	if len(key) != keySize {
		return "", fmt.Errorf("envelope: key must be %d bytes", keySize)
	}
	if kid == "" || strings.Contains(kid, ":") {
		return "", errors.New("envelope: invalid key id")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, aad)
	ct, tag := sealed[:len(sealed)-tagSize], sealed[len(sealed)-tagSize:]
	return strings.Join([]string{version, kid, b64.EncodeToString(iv), b64.EncodeToString(ct), b64.EncodeToString(tag)}, ":"), nil
}

// KeyID returns the key id of a ciphertext without decrypting it.
func KeyID(s string) (string, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 5 || parts[0] != version || parts[1] == "" {
		return "", ErrFormat
	}
	return parts[1], nil
}

// Open decrypts s with key, checking that it was sealed under kid and aad.
func Open(key []byte, kid string, aad []byte, s string) ([]byte, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 5 || parts[0] != version {
		return nil, ErrFormat
	}
	if parts[1] != kid {
		return nil, ErrKeyID
	}
	iv, err1 := b64.DecodeString(parts[2])
	ct, err2 := b64.DecodeString(parts[3])
	tag, err3 := b64.DecodeString(parts[4])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != ivSize || len(tag) != tagSize {
		return nil, ErrFormat
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("envelope: key must be %d bytes", keySize)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, iv, append(ct, tag...), aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewKey returns 32 random bytes.
func NewKey() []byte {
	k := make([]byte, keySize)
	if _, err := rand.Read(k); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return k
}

// KEK is the key-encryption key of the service.
type KEK struct {
	id  string
	key []byte
}

// ParseKEK decodes a base64 (standard or URL, padded or not) 32-byte KEK.
func ParseKEK(text string) (*KEK, error) {
	text = strings.TrimSpace(text)
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err = enc.DecodeString(text); err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("envelope: KEK is not valid base64")
	}
	if len(raw) != keySize {
		return nil, fmt.Errorf("envelope: KEK must decode to %d bytes, got %d", keySize, len(raw))
	}
	return NewKEK(raw), nil
}

// NewKEK builds a KEK from 32 raw bytes.
func NewKEK(raw []byte) *KEK {
	sum := sha256.Sum256(raw)
	return &KEK{id: hex.EncodeToString(sum[:])[:16], key: append([]byte(nil), raw...)}
}

// ID returns the KEK id: the first 16 hex characters of SHA-256(KEK).
func (k *KEK) ID() string { return k.id }

// DEKAAD returns the AAD of a wrapped DEK row.
func DEKAAD(dekID, tenant string) []byte {
	return AAD("apple_edge.data_keys", "dek_wrapped", dekID, tenant)
}

// Wrap encrypts a DEK for the apple_edge.data_keys row dekID of tenant ("" for the instance).
func (k *KEK) Wrap(dekID, tenant string, dek []byte) (string, error) {
	if len(dek) != keySize {
		return "", fmt.Errorf("envelope: DEK must be %d bytes", keySize)
	}
	return Seal(k.key, k.id, DEKAAD(dekID, tenant), dek)
}

// Unwrap decrypts a wrapped DEK.
func (k *KEK) Unwrap(dekID, tenant, wrapped string) ([]byte, error) {
	dek, err := Open(k.key, k.id, DEKAAD(dekID, tenant), wrapped)
	if err != nil {
		return nil, err
	}
	if len(dek) != keySize {
		return nil, ErrFormat
	}
	return dek, nil
}

// DEK is an unwrapped data-encryption key.
type DEK struct {
	ID  string
	key []byte
}

// NewDEK returns a DEK with id and raw key bytes.
func NewDEK(id string, raw []byte) *DEK { return &DEK{ID: id, key: raw} }

// Seal encrypts plaintext for the given column coordinates.
func (d *DEK) Seal(schemaTable, column, pk, tenant string, plaintext []byte) (string, error) {
	return Seal(d.key, d.ID, AAD(schemaTable, column, pk, tenant), plaintext)
}

// Open decrypts a ciphertext for the given column coordinates.
func (d *DEK) Open(schemaTable, column, pk, tenant, s string) ([]byte, error) {
	return Open(d.key, d.ID, AAD(schemaTable, column, pk, tenant), s)
}
