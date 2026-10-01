// Package obs provides the observability primitives of apple-edge: a JSON
// logger that keeps only allow-listed keys (no personal data), adapters for
// the loggers of the embedded libraries, Prometheus metrics and the
// pseudonymisation of enrollment ids.
package obs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	kitlog "github.com/go-kit/kit/log"
	nanolog "github.com/micromdm/nanolib/log"
)

// allowed lists the keys that may appear in a log line. Any other key is
// dropped, including keys added by the embedded libraries.
var allowed = map[string]bool{
	"ts": true, "level": true, "msg": true, "err": true, "component": true, "route": true,
	"method": true, "status": true, "duration_ms": true, "tenant": true, "eref": true,
	"request_id": true, "command_uuid": true, "request_type": true, "message_type": true,
	"topic": true, "outcome": true, "count": true, "version": true, "actor": true,
}

// renamed maps library keys onto allowed keys.
var renamed = map[string]string{
	"error":       "err",
	"http_status": "status",
	"service":     "component",
	"handler":     "component",
	"storage":     "component",
}

// Logger writes one JSON object per line. It is safe for concurrent use.
type Logger struct {
	sink  *sink
	debug bool
	kvs   []any
}

type sink struct {
	mu     sync.Mutex
	w      io.Writer
	pseudo atomic.Pointer[[]byte]
	now    func() time.Time
}

// NewLogger returns a logger writing to w. debug enables the debug level.
func NewLogger(w io.Writer, debug bool) *Logger {
	return &Logger{sink: &sink{w: w, now: time.Now}, debug: debug}
}

// SetPseudonymKey sets the HMAC key used to turn enrollment ids into erefs.
// Until it is set, enrollment ids are dropped from the logs.
func (l *Logger) SetPseudonymKey(key []byte) {
	k := append([]byte(nil), key...)
	l.sink.pseudo.Store(&k)
}

// Eref returns the pseudonym of an enrollment id ("" if no key is set).
func (l *Logger) Eref(enrollmentID string) string {
	return Eref(l.pseudonymKey(), enrollmentID)
}

func (l *Logger) pseudonymKey() []byte {
	if p := l.sink.pseudo.Load(); p != nil {
		return *p
	}
	return nil
}

var erefEnc = base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").WithPadding(base32.NoPadding)

// Eref returns the first 12 base32 characters of HMAC-SHA256(key, id).
func Eref(key []byte, enrollmentID string) string {
	if len(key) == 0 || enrollmentID == "" {
		return ""
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(enrollmentID))
	return erefEnc.EncodeToString(m.Sum(nil))[:12]
}

// With returns a logger that adds kvs to every line.
func (l *Logger) With(kvs ...any) *Logger {
	n := &Logger{sink: l.sink, debug: l.debug}
	n.kvs = append(append(make([]any, 0, len(l.kvs)+len(kvs)), l.kvs...), kvs...)
	return n
}

// Info logs at the info level.
func (l *Logger) Info(kvs ...any) { l.write("info", kvs) }

// Debug logs at the debug level (dropped unless enabled).
func (l *Logger) Debug(kvs ...any) {
	if l.debug {
		l.write("debug", kvs)
	}
}

// Error logs at the error level.
func (l *Logger) Error(kvs ...any) { l.write("error", kvs) }

func (l *Logger) write(level string, kvs []any) {
	all := make([]any, 0, len(l.kvs)+len(kvs))
	all = append(append(all, l.kvs...), kvs...)
	fields := make(map[string]any, 8)
	order := make([]string, 0, 8)
	set := func(k string, v any) {
		if _, dup := fields[k]; !dup {
			order = append(order, k)
		}
		fields[k] = v
	}
	for i := 0; i+1 < len(all); i += 2 {
		k, ok := all[i].(string)
		if !ok {
			continue
		}
		if r, ok := renamed[k]; ok {
			k = r
		}
		v := all[i+1]
		switch k {
		case "id":
			if e := Eref(l.pseudonymKey(), fmt.Sprint(v)); e != "" {
				set("eref", e)
			}
			continue
		case "ts", "level":
			continue
		}
		if !allowed[k] {
			continue
		}
		set(k, sanitizeValue(k, v))
	}
	var b strings.Builder
	b.WriteString(`{"ts":`)
	writeJSON(&b, l.sink.now().UTC().Format(time.RFC3339Nano))
	b.WriteString(`,"level":`)
	writeJSON(&b, level)
	if m, ok := fields["msg"]; ok {
		b.WriteString(`,"msg":`)
		writeJSON(&b, m)
	}
	for _, k := range order {
		if k == "msg" {
			continue
		}
		b.WriteString(",")
		writeJSON(&b, k)
		b.WriteString(":")
		writeJSON(&b, fields[k])
	}
	b.WriteString("}\n")
	l.sink.mu.Lock()
	_, _ = io.WriteString(l.sink.w, b.String())
	l.sink.mu.Unlock()
}

func writeJSON(b *strings.Builder, v any) {
	out, err := json.Marshal(v)
	if err != nil {
		out, _ = json.Marshal(fmt.Sprint(v))
	}
	b.Write(out)
}

func sanitizeValue(key string, v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return x
	case time.Duration:
		return x.Milliseconds()
	case error:
		return Mask(x.Error())
	case fmt.Stringer:
		return maskIfFree(key, x.String())
	case string:
		return maskIfFree(key, x)
	default:
		return maskIfFree(key, fmt.Sprint(x))
	}
}

// Keys whose values are produced by apple-edge itself and never carry
// free text from a device.
var structuredKeys = map[string]bool{
	"tenant": true, "eref": true, "request_id": true, "command_uuid": true,
	"request_type": true, "message_type": true, "topic": true, "route": true,
	"method": true, "component": true, "outcome": true, "version": true, "actor": true,
}

func maskIfFree(key, s string) string {
	if structuredKeys[key] {
		if len(s) > 200 {
			return s[:200]
		}
		return s
	}
	return Mask(s)
}

var (
	plistRe = regexp.MustCompile(`(?s)(<\?xml|<plist|<dict>|<!DOCTYPE).*`)
	uuidRe  = regexp.MustCompile(`[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`)
	longRe  = regexp.MustCompile(`[A-Za-z0-9+/=_-]{17,}`)
	ipv4Re  = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?\b`)
	ipv6Re  = regexp.MustCompile(`\[?\b([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b\]?(:\d{1,5})?`)
)

// Mask hides everything that may identify a device in a free-text message:
// plists, UUIDs, IP addresses, and hex, base64 or identifier-like strings
// longer than 16 characters.
func Mask(s string) string {
	s = plistRe.ReplaceAllString(s, "[plist]")
	s = uuidRe.ReplaceAllString(s, "[uuid]")
	s = ipv4Re.ReplaceAllString(s, "[ip]")
	s = ipv6Re.ReplaceAllString(s, "[ip]")
	s = longRe.ReplaceAllString(s, "[redacted]")
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}

// Nano adapts l to the logger interface of NanoMDM and nanolib.
func (l *Logger) Nano() nanolog.Logger { return nanoLogger{l} }

type nanoLogger struct{ l *Logger }

func (n nanoLogger) Info(kvs ...interface{})                { n.l.Info(kvs...) }
func (n nanoLogger) Debug(kvs ...interface{})               { n.l.Debug(kvs...) }
func (n nanoLogger) With(kvs ...interface{}) nanolog.Logger { return nanoLogger{n.l.With(kvs...)} }

// Kit adapts l to the go-kit logger used by the SCEP library.
func (l *Logger) Kit() kitlog.Logger { return kitLogger{l} }

type kitLogger struct{ l *Logger }

func (k kitLogger) Log(kvs ...interface{}) error {
	k.l.Info(kvs...)
	return nil
}

// ErrString returns a masked error string suitable for logs and events.
func ErrString(err error) string {
	if err == nil {
		return ""
	}
	return Mask(err.Error())
}
