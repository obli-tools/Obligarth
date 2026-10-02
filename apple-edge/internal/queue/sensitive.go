package queue

import (
	"bytes"
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/plistlimit"
)

// A command plist stays in clear in nanomdm.commands until the device
// acknowledges it, and in the backups of the database meanwhile. The only
// secrets it may carry are the placeholder of the UnlockToken, replaced at
// delivery, and payloads encrypted for the device (EncryptedPayloadContent).
// The brain checks this before it sends a command; apple-edge checks it again
// at enqueueing time, with the same closed rules, so that a regression of
// the brain is refused (422 secret_in_command) instead of being stored:
//
//  1. a non-empty string or data value whose key is a known secret key
//     (secretKeyRe), anywhere in the Command dictionary or in a configuration
//     profile it carries;
//  2. the PayloadContent of a PKCS#12 payload (com.apple.security.pkcs12);
//  3. a Challenge or a private key of a SCEP or ACME payload (rule 1);
//  4. a string or data that holds a PEM private key.
//
// A data value that decodes to a configuration profile (XML or binary
// property list, possibly inside a CMS SignedData) is examined as well; the
// content of an EncryptedPayloadContent is opaque and accepted. The payload
// of an InstallProfile command must be such a profile.

// secretKeyRe lists the keys that hold a secret in Apple's payloads and
// commands, as a whole key or as the end of a key after a lower-case letter
// (RemovalPassword, XAuthPassword, UserPassword...): the closed list of the
// brain's scanner. Boolean or numeric values (PasswordRequired...) are never
// secrets.
var secretKeyRe = regexp.MustCompile(`(^|[a-z])(Password|Passphrase|Secret|SharedSecret|Challenge|PIN|PrivateKey|AuthPassword|IncomingPassword|OutgoingPassword|UnlockToken|BootstrapToken)$`)

var pemPrivateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

// Bounds of the examination of a command (the brain is authenticated, but a
// profile is decoded once more here: the same bounded pass as for devices).
var commandLimits = plistlimit.Limits{MaxDepth: 64, MaxElements: 500000}

const (
	maxProfileNesting = 2 // a profile inside a profile inside a command
	scanTimeout       = 2 * time.Second
)

// errSecret builds the refusal; where names keys only, never a value.
func errSecret(where string) error {
	if len(where) > 200 {
		where = where[:200]
	}
	return apierr.Unprocessable("secret_in_command",
		"the command carries a secret in clear ("+where+"): deliver it encrypted for the device (EncryptedPayloadContent) or through a placeholder")
}

// checkSecrets refuses a command plist that carries a secret in clear.
// requestType comes from the decoded command; the placeholder of the
// UnlockToken was validated before.
func checkSecrets(plistBytes []byte, requestType string) error {
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	if _, err := plistlimit.Check(ctx, plistBytes, commandLimits); err != nil {
		return apierr.Unprocessable("validation_failed", "the command plist exceeds the limits of the examination")
	}
	var root map[string]any
	if err := plist.Unmarshal(plistBytes, &root); err != nil {
		return apierr.Unprocessable("validation_failed", "command_plist_b64 is not a valid MDM command")
	}
	cmd, _ := root["Command"].(map[string]any)
	s := &scanner{ctx: ctx}
	if err := s.walk(cmd, "Command", 0, 0); err != nil {
		return err
	}
	if requestType == "InstallProfile" {
		payload, _ := cmd["Payload"].([]byte)
		if p, ok := s.profileOf(payload); !ok || p == nil {
			return apierr.Unprocessable("validation_failed", "the Payload of InstallProfile is not a readable configuration profile")
		}
	}
	return nil
}

type scanner struct {
	ctx context.Context
}

// walk examines a value at path; nesting counts the profiles traversed.
func (s *scanner) walk(v any, path string, depth, nesting int) error {
	if depth > commandLimits.MaxDepth {
		return apierr.Unprocessable("validation_failed", "the command is nested too deeply")
	}
	switch x := v.(type) {
	case map[string]any:
		if t, _ := x["PayloadType"].(string); t == "com.apple.security.pkcs12" {
			if c, ok := x["PayloadContent"].([]byte); ok && len(c) > 0 {
				return errSecret(path + ".PayloadContent (PKCS#12)")
			}
			if c, ok := x["PayloadContent"].(string); ok && c != "" {
				return errSecret(path + ".PayloadContent (PKCS#12)")
			}
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := x[k]
			if k == "EncryptedPayloadContent" {
				continue // opaque: encrypted for the device
			}
			if secretKeyRe.MatchString(k) && nonEmpty(val) && !isUnlockPlaceholder(k, val) {
				return errSecret(path + "." + k)
			}
			if err := s.walk(val, path+"."+k, depth+1, nesting); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range x {
			if err := s.walk(e, path+"["+strconv.Itoa(i)+"]", depth+1, nesting); err != nil {
				return err
			}
		}
	case string:
		if pemPrivateKeyRe.MatchString(x) {
			return errSecret(path + " (PEM private key)")
		}
	case []byte:
		if pemPrivateKeyRe.Match(x) {
			return errSecret(path + " (PEM private key)")
		}
		if nesting >= maxProfileNesting {
			return nil
		}
		if p, ok := s.profileOf(x); ok && p != nil {
			return s.walk(p, path+">profile", 0, nesting+1)
		}
	}
	return nil
}

// profileOf decodes b as a configuration profile: a property list (XML or
// binary), possibly the content of a CMS SignedData. ok is false when b looks
// like a profile but cannot be examined; p is nil when b is something else.
func (s *scanner) profileOf(b []byte) (p map[string]any, ok bool) {
	content := b
	if len(b) > 0 && b[0] == 0x30 { // DER: a signed profile
		p7, err := pkcs7.Parse(b)
		if err != nil || len(p7.Content) == 0 {
			return nil, true // not a signed property list: not a profile
		}
		content = p7.Content
	}
	trimmed := bytes.TrimLeft(content, "\xef\xbb\xbf \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("<?xml")) && !bytes.HasPrefix(trimmed, []byte("<plist")) &&
		!bytes.HasPrefix(trimmed, []byte("<!DOCTYPE")) && !bytes.HasPrefix(trimmed, []byte("bplist00")) {
		return nil, true
	}
	if _, err := plistlimit.Check(s.ctx, trimmed, commandLimits); err != nil {
		return nil, false
	}
	var m map[string]any
	if err := plist.Unmarshal(trimmed, &m); err != nil {
		return nil, false
	}
	if t, _ := m["PayloadType"].(string); !strings.EqualFold(t, "Configuration") {
		return nil, true
	}
	return m, true
}

func nonEmpty(v any) bool {
	switch x := v.(type) {
	case string:
		return x != ""
	case []byte:
		return len(x) > 0
	}
	return false
}

func isUnlockPlaceholder(key string, v any) bool {
	s, ok := v.(string)
	return ok && key == "UnlockToken" && s == UnlockPlaceholder
}
