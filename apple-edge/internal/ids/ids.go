// Package ids holds the identifier formats shared by every layer: opaque
// tenant keys, namespaced enrollment ids and random UUIDs.
package ids

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// KeyAlphabet is the alphabet of tenant keys and SCEP challenges
// (no l, o, 0 or 1).
const KeyAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

// Sep separates the tenant key from the device identifier in the
// enrollment ids stored by NanoMDM ("<key>_<UDID>"). It cannot appear in a key.
const Sep = "_"

var (
	b32     = base32.NewEncoding(KeyAlphabet).WithPadding(base32.NoPadding)
	keyRe   = regexp.MustCompile(`^[a-km-np-z2-9]{16}$`)
	rawIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	uuidRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// NewTenantKey returns a new random tenant key (10 bytes, 80 bits, 16 chars).
func NewTenantKey() string {
	return RandomString(10)
}

// RandomString returns n random bytes encoded with KeyAlphabet.
func RandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return b32.EncodeToString(b)
}

// ValidTenantKey reports whether k is a well-formed tenant key.
func ValidTenantKey(k string) bool { return keyRe.MatchString(k) }

// ValidRawID reports whether id is acceptable as a device identifier
// (UDID or EnrollmentID) before namespacing. ':' is excluded because
// NanoMDM uses it to separate user channels.
func ValidRawID(id string) bool { return rawIDRe.MatchString(id) }

// ValidUUID reports whether s looks like a UUID (any version, any case).
func ValidUUID(s string) bool { return uuidRe.MatchString(s) }

// Namespace returns "<key>_<id>", or "" for an empty id.
func Namespace(key, id string) string {
	if id == "" {
		return ""
	}
	return key + Sep + id
}

// SplitNamespaced returns the tenant key and the device part of a
// namespaced enrollment id. ok is false if id is not namespaced.
func SplitNamespaced(id string) (key, rest string, ok bool) {
	key, rest, ok = strings.Cut(id, Sep)
	if !ok || !ValidTenantKey(key) || rest == "" {
		return "", "", false
	}
	return key, rest, true
}

// BelongsTo reports whether the namespaced enrollment id belongs to tenant key.
func BelongsTo(key, id string) bool {
	k, _, ok := SplitNamespaced(id)
	return ok && k == key
}

// NewUUID returns a random (version 4) UUID in lower case.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ErrInvalid is returned by parsers of this package.
var ErrInvalid = errors.New("invalid identifier")
