package outbox

import (
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/micromdm/plist"
)

// Redacted replaces values the brain must not receive.
const Redacted = "(redacted)"

// maxSafeInteger is the largest integer a JSON number carries exactly in JavaScript.
const maxSafeInteger = 1 << 53

// PlistToJSON converts a device plist into a JSON-friendly value:
// integers beyond 2^53 become decimal strings, dates RFC 3339 UTC strings
// and data standard base64 strings.
func PlistToJSON(raw []byte) (map[string]any, error) {
	var v map[string]interface{}
	if err := plist.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	out, _ := convert(v).(map[string]any)
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

func convert(v interface{}) any {
	switch x := v.(type) {
	case map[string]interface{}:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = convert(e)
		}
		return m
	case []interface{}:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = convert(e)
		}
		return a
	case uint64:
		if x <= maxSafeInteger {
			return x
		}
		return strconv.FormatUint(x, 10)
	case int64:
		if x >= -maxSafeInteger && x <= maxSafeInteger {
			return x
		}
		return strconv.FormatInt(x, 10)
	case float64:
		if math.IsInf(x, 0) || math.IsNaN(x) {
			return fmt.Sprint(x)
		}
		return x
	case float32:
		f := float64(x)
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return fmt.Sprint(f)
		}
		return f
	case []byte:
		return base64.StdEncoding.EncodeToString(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	case string, bool, nil:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// Secret keys never forwarded in clear, wherever they appear.
var secretKeys = map[string]bool{
	"UnlockToken":              true,
	"BootstrapToken":           true,
	"ActivationLockBypassCode": true,
	"PushMagic":                true,
}

// RedactTokenUpdate removes the push trio and the UnlockToken of a
// converted TokenUpdate. It reports whether an UnlockToken was present.
func RedactTokenUpdate(m map[string]any) (hadUnlockToken bool) {
	_, hadUnlockToken = m["UnlockToken"]
	delete(m, "UnlockToken")
	for _, k := range []string{"PushMagic", "Token"} {
		if _, ok := m[k]; ok {
			m[k] = Redacted
		}
	}
	RedactSecrets(m)
	return hadUnlockToken
}

// SecretRef is the placeholder of a secret kept by apple-edge.
func SecretRef(id string) map[string]any { return map[string]any{"$secret_ref": id} }

func isSecretRef(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	_, ok = m["$secret_ref"].(string)
	return ok
}

// RedactSecrets replaces every secret key, at any depth, by "(redacted)",
// except values already replaced by a secret reference.
func RedactSecrets(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if secretKeys[k] {
				if !isSecretRef(e) {
					x[k] = Redacted
				}
				continue
			}
			RedactSecrets(e)
		}
	case []any:
		for _, e := range x {
			RedactSecrets(e)
		}
	}
}

// Envelope keys of a command result, reported separately in the event.
var resultEnvelope = []string{"CommandUUID", "Status", "UDID", "EnrollmentID", "EnrollmentUserID",
	"UserID", "UserShortName", "UserLongName", "ErrorChain", "RequestType"}

// SplitResult separates the envelope of a converted command result from
// its content, returning the error chain and the remaining result.
func SplitResult(m map[string]any) (errorChain any, result map[string]any) {
	errorChain = m["ErrorChain"]
	for _, k := range resultEnvelope {
		delete(m, k)
	}
	return errorChain, m
}
