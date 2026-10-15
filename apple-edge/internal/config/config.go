// Package config reads and validates the environment of apple-edge.
// Secrets are never passed in variables: only paths to secret files.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/netip"
	"net/url"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Environments.
const (
	EnvProduction  = "production"
	EnvDevelopment = "development"
)

// Cross-tenant policies (device id already active in another tenant).
const (
	PolicyRefuse = "refuse"
	PolicyAllow  = "allow"
)

// Config is the validated configuration.
type Config struct {
	Env        string
	PublicBase string // scheme://host[:port], no trailing slash

	DeviceListen   string
	InternalListen string

	DatabaseURL    string
	DBPasswordFile string
	DBMaxConns     int

	AdminDatabaseURL    string
	AppDBPasswordFile   string
	OutboxReaderGrantee string

	KEKFile         string
	KEKPreviousFile string

	APITokenFile     string
	APITokenNextFile string

	DDMURL         string
	DDMHMACKeyFile string

	APNsURL         string
	APNsExtraCAFile string
	APNsExpiration  time.Duration
	ReleaseAfter410 time.Duration

	ADEBaseURL         string
	ADEProtocolVersion int
	ADESyncInterval    time.Duration

	// MachineInfoExtraRootFile adds a test PKI for MachineInfo signatures
	// (development only): its self-signed certificates as roots, its other
	// CA certificates as pinned device CAs.
	MachineInfoExtraRootFile string

	CrossTenantPolicy string
	DeviceCertDays    int
	CAYears           int

	SeenBatchInterval time.Duration
	OutboxRetention   time.Duration
	RetireAfter       time.Duration

	BodyCheckin    int64
	BodyMDM        int64
	BodySCEP       int64
	MaxHeaderBytes int
	MaxInflight    int
	LargeBodySlots int
	// LargeBodyBudget and LargeBodyTenant bound the bytes of large bodies
	// in flight, overall and per tenant (AE-B0-R3).
	LargeBodyBudget int64
	LargeBodyTenant int64

	TimeoutCheckin time.Duration
	TimeoutMDM     time.Duration
	TimeoutSCEP    time.Duration

	TrustedProxies []netip.Prefix
	FailLimitPerIP int

	ShutdownDrain   time.Duration
	ShutdownTimeout time.Duration

	LogLevel string
}

// Load reads the configuration from getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	p := &parser{getenv: getenv}
	c := &Config{
		Env:                      p.str("EDGE_ENV", EnvProduction),
		PublicBase:               strings.TrimRight(p.str("MDM_PUBLIC_BASE", ""), "/"),
		DeviceListen:             p.str("EDGE_DEVICE_LISTEN", ":9000"),
		InternalListen:           p.str("EDGE_INTERNAL_LISTEN", ":9100"),
		DatabaseURL:              p.str("EDGE_DATABASE_URL", ""),
		DBPasswordFile:           p.str("EDGE_DB_PASSWORD_FILE", ""),
		DBMaxConns:               p.integer("EDGE_DB_MAX_CONNS", 32, 4, 512),
		AdminDatabaseURL:         p.str("EDGE_ADMIN_DATABASE_URL", ""),
		AppDBPasswordFile:        p.str("EDGE_APP_DB_PASSWORD_FILE", ""),
		OutboxReaderGrantee:      p.str("EDGE_OUTBOX_READER_GRANTEE", "obligarth"),
		KEKFile:                  p.str("EDGE_KEK_FILE", ""),
		KEKPreviousFile:          p.str("EDGE_KEK_PREVIOUS_FILE", ""),
		APITokenFile:             p.str("EDGE_API_TOKEN_FILE", ""),
		APITokenNextFile:         p.str("EDGE_API_TOKEN_NEXT_FILE", ""),
		DDMURL:                   p.str("EDGE_DDM_URL", "http://server:3001/internal/apple-edge/ddm"),
		DDMHMACKeyFile:           p.str("EDGE_DDM_HMAC_KEY_FILE", ""),
		APNsURL:                  strings.TrimRight(p.str("EDGE_APNS_URL", "https://api.push.apple.com"), "/"),
		APNsExtraCAFile:          p.str("EDGE_APNS_EXTRA_CA_FILE", ""),
		APNsExpiration:           p.duration("EDGE_APNS_EXPIRATION", 72*time.Hour, 0, 30*24*time.Hour),
		ReleaseAfter410:          p.duration("EDGE_RELEASE_AFTER_410", 168*time.Hour, 0, 90*24*time.Hour),
		ADEBaseURL:               strings.TrimRight(p.str("EDGE_ADE_BASE_URL", "https://mdmenrollment.apple.com"), "/"),
		ADEProtocolVersion:       p.integer("EDGE_ADE_PROTOCOL_VERSION", 10, 1, 99),
		ADESyncInterval:          p.duration("EDGE_ADE_SYNC_INTERVAL", 30*time.Minute, time.Second, 24*time.Hour),
		MachineInfoExtraRootFile: p.str("EDGE_MACHINE_INFO_EXTRA_ROOT_FILE", ""),
		CrossTenantPolicy:        p.str("EDGE_CROSS_TENANT_POLICY", PolicyRefuse),
		DeviceCertDays:           p.integer("EDGE_DEVICE_CERT_DAYS", 1825, 1, 3650),
		CAYears:                  p.integer("EDGE_CA_YEARS", 10, 1, 30),
		SeenBatchInterval:        p.duration("EDGE_SEEN_BATCH_INTERVAL", 5*time.Minute, time.Second, 24*time.Hour),
		OutboxRetention:          p.duration("EDGE_OUTBOX_RETENTION", 168*time.Hour, time.Minute, 90*24*time.Hour),
		RetireAfter:              p.duration("EDGE_RETIRE_AFTER", 720*time.Hour, 0, 365*24*time.Hour),
		BodyCheckin:              p.size("EDGE_BODY_CHECKIN", 4<<20, 1<<10, 32<<20),
		BodyMDM:                  p.size("EDGE_BODY_MDM", 16<<20, 1<<10, 32<<20),
		BodySCEP:                 p.size("EDGE_BODY_SCEP", 256<<10, 1<<10, 2<<20),
		MaxHeaderBytes:           int(p.size("EDGE_MAX_HEADER_BYTES", 64<<10, 4<<10, 1<<20)),
		MaxInflight:              p.integer("EDGE_MAX_INFLIGHT", 1024, 1, 1<<20),
		LargeBodySlots:           p.integer("EDGE_LARGE_BODY_SLOTS", 16, 1, 1024),
		TimeoutCheckin:           p.duration("EDGE_TIMEOUT_CHECKIN", 15*time.Second, time.Second, 5*time.Minute),
		TimeoutMDM:               p.duration("EDGE_TIMEOUT_MDM", 30*time.Second, time.Second, 5*time.Minute),
		TimeoutSCEP:              p.duration("EDGE_TIMEOUT_SCEP", 10*time.Second, time.Second, 5*time.Minute),
		FailLimitPerIP:           p.integer("EDGE_FAIL_LIMIT_PER_IP", 60, 0, 1<<20),
		ShutdownDrain:            p.duration("EDGE_SHUTDOWN_DRAIN", 5*time.Second, 0, time.Minute),
		ShutdownTimeout:          p.duration("EDGE_SHUTDOWN_TIMEOUT", 20*time.Second, time.Second, 5*time.Minute),
		LogLevel:                 p.str("EDGE_LOG_LEVEL", "info"),
	}
	c.TrustedProxies = p.prefixes("EDGE_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	budget := DefaultLargeBodyBudget(c.BodyMDM, memoryLimit())
	c.LargeBodyBudget = p.size("EDGE_LARGE_BODY_BUDGET", budget, 1<<20, 1<<30)
	c.LargeBodyTenant = p.size("EDGE_LARGE_BODY_TENANT", min(c.LargeBodyBudget, c.BodyMDM+(1<<20)), 1<<20, 1<<30)
	if p.err != nil {
		return nil, p.err
	}
	if c.LargeBodyTenant > c.LargeBodyBudget || c.LargeBodyTenant <= c.BodyMDM {
		return nil, fmt.Errorf("EDGE_LARGE_BODY_TENANT (%d bytes) must exceed EDGE_BODY_MDM (%d bytes) and stay within the large-body budget (%d bytes; "+
			"EDGE_LARGE_BODY_BUDGET, by default a sixteenth of GOMEMLIMIT): raise GOMEMLIMIT and the container's memory limit, or lower EDGE_BODY_MDM",
			c.LargeBodyTenant, c.BodyMDM, c.LargeBodyBudget)
	}
	if c.Env != EnvProduction && c.Env != EnvDevelopment {
		return nil, fmt.Errorf("EDGE_ENV must be %q or %q", EnvProduction, EnvDevelopment)
	}
	if c.CrossTenantPolicy != PolicyRefuse && c.CrossTenantPolicy != PolicyAllow {
		return nil, fmt.Errorf("EDGE_CROSS_TENANT_POLICY must be %q or %q", PolicyRefuse, PolicyAllow)
	}
	if c.LogLevel != "info" && c.LogLevel != "debug" {
		return nil, errors.New(`EDGE_LOG_LEVEL must be "info" or "debug"`)
	}
	return c, nil
}

// memoryLimit is the soft memory limit of the Go runtime (GOMEMLIMIT),
// math.MaxInt64 when none is set; tests replace it.
var memoryLimit = func() int64 { return debug.SetMemoryLimit(-1) }

// LargeBodyAmplification is the memory a large command result costs per
// byte while it is checked, decoded, converted and written to the outbox:
// measured on lot C0 at 14 times its size (a signed result of 16 MiB of a
// queued InstalledApplicationList: 228 MiB of committed memory over the
// idle process, under GOMEMLIMIT=410MiB), rounded up for the garbage the
// collector has not yet returned.
const LargeBodyAmplification = 16

// DefaultLargeBodyBudget returns the default byte budget of the large
// bodies in flight: two bodies of the largest size of the /mdm route and
// 2 MiB, within a sixteenth of the memory limit of the process when one is
// set (GOMEMLIMIT, 80 % of the container's mem_limit: with 410 MiB, 25.6 MiB,
// one body of 16 MiB and smaller ones at once).
func DefaultLargeBodyBudget(bodyMDM, memLimit int64) int64 {
	b := 2*bodyMDM + 2<<20
	if memLimit > 0 && memLimit < math.MaxInt64 {
		b = min(b, memLimit/LargeBodyAmplification)
	}
	return max(b, 1<<20)
}

// ValidateServe checks what the serve command needs.
func (c *Config) ValidateServe() error {
	var missing []string
	for name, v := range map[string]string{
		"MDM_PUBLIC_BASE": c.PublicBase, "EDGE_DATABASE_URL": c.DatabaseURL,
		"EDGE_DB_PASSWORD_FILE": c.DBPasswordFile, "EDGE_KEK_FILE": c.KEKFile,
		"EDGE_API_TOKEN_FILE": c.APITokenFile, "EDGE_DDM_HMAC_KEY_FILE": c.DDMHMACKeyFile,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("missing required settings: %s", strings.Join(missing, ", "))
	}
	if err := c.validatePublicBase(); err != nil {
		return err
	}
	return c.validateUpstreams()
}

// validateUpstreams checks the URLs of APNs, the ADE API and the brain.
// Test authorities and plain HTTP towards Apple's stand-ins are accepted
// with EDGE_ENV=development only.
func (c *Config) validateUpstreams() error {
	dev := c.Env == EnvDevelopment
	if err := baseURL("EDGE_APNS_URL", c.APNsURL, false); err != nil {
		return err
	}
	if err := baseURL("EDGE_ADE_BASE_URL", c.ADEBaseURL, dev); err != nil {
		return err
	}
	u, err := url.Parse(c.DDMURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("EDGE_DDM_URL must be an absolute http(s) URL, e.g. http://server:3001/internal/apple-edge/ddm")
	}
	if !dev && (c.APNsExtraCAFile != "" || c.MachineInfoExtraRootFile != "") {
		return errors.New("EDGE_APNS_EXTRA_CA_FILE and EDGE_MACHINE_INFO_EXTRA_ROOT_FILE are accepted with EDGE_ENV=development only")
	}
	return nil
}

// baseURL checks an https URL without path (http too when allowHTTP).
func baseURL(name, raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("%s must be an absolute URL without path", name)
	}
	if u.Scheme == "https" || (u.Scheme == "http" && allowHTTP) {
		return nil
	}
	if u.Scheme == "http" {
		return fmt.Errorf("%s must use https (http is accepted with EDGE_ENV=development only)", name)
	}
	return fmt.Errorf("%s must use https", name)
}

// ValidateMigrate checks what the migrate command needs.
func (c *Config) ValidateMigrate() error {
	if c.AdminDatabaseURL == "" || c.AppDBPasswordFile == "" {
		return errors.New("missing required settings: EDGE_ADMIN_DATABASE_URL, EDGE_APP_DB_PASSWORD_FILE")
	}
	if c.OutboxReaderGrantee != "" && !identRe(c.OutboxReaderGrantee) {
		return errors.New("EDGE_OUTBOX_READER_GRANTEE is not a valid role name")
	}
	return nil
}

// ValidateKEKRotate checks what "kek rotate" needs.
func (c *Config) ValidateKEKRotate() error {
	if c.DatabaseURL == "" || c.DBPasswordFile == "" || c.KEKFile == "" || c.KEKPreviousFile == "" {
		return errors.New("missing required settings: EDGE_DATABASE_URL, EDGE_DB_PASSWORD_FILE, EDGE_KEK_FILE, EDGE_KEK_PREVIOUS_FILE")
	}
	return nil
}

// ValidateSigningImport checks what "signing-identity import" needs.
func (c *Config) ValidateSigningImport() error {
	if c.DatabaseURL == "" || c.DBPasswordFile == "" || c.KEKFile == "" {
		return errors.New("missing required settings: EDGE_DATABASE_URL, EDGE_DB_PASSWORD_FILE, EDGE_KEK_FILE")
	}
	return nil
}

func (c *Config) validatePublicBase() error {
	u, err := url.Parse(c.PublicBase)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("MDM_PUBLIC_BASE must be an absolute URL without path, e.g. https://mdm.example.net")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if c.Env != EnvDevelopment {
			return errors.New("MDM_PUBLIC_BASE must use https (http is accepted with EDGE_ENV=development only)")
		}
	default:
		return errors.New("MDM_PUBLIC_BASE must use https")
	}
	return nil
}

// NonrootUID is the user of the image (gcr.io/distroless/static:nonroot):
// the secret files of apple-edge must be readable by it.
const NonrootUID = 65532

// ReadSecretFile reads a secret file and trims surrounding white space.
func ReadSecretFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("no secret file configured")
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrPermission) {
		// The image runs as the distroless user nonroot: a secret file of
		// compose is a bind mount that keeps its owner and mode on the host.
		return "", fmt.Errorf("reading secret file: permission denied: apple-edge runs as uid %d, "+
			"make the file readable by it (install.sh: chown %d:%d, mode 600)", NonrootUID, NonrootUID, NonrootUID)
	}
	if err != nil {
		return "", fmt.Errorf("reading secret file: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("secret file is empty")
	}
	return s, nil
}

type parser struct {
	getenv func(string) string
	err    error
}

func (p *parser) fail(name string, err error) {
	if p.err == nil {
		p.err = fmt.Errorf("%s: %w", name, err)
	}
}

func (p *parser) str(name, def string) string {
	if v := strings.TrimSpace(p.getenv(name)); v != "" {
		return v
	}
	return def
}

func (p *parser) integer(name string, def, min, max int) int {
	v := strings.TrimSpace(p.getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		p.fail(name, fmt.Errorf("must be an integer between %d and %d", min, max))
		return def
	}
	return n
}

func (p *parser) duration(name string, def, min, max time.Duration) time.Duration {
	v := strings.TrimSpace(p.getenv(name))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < min || d > max {
		p.fail(name, fmt.Errorf("must be a duration between %s and %s", min, max))
		return def
	}
	return d
}

// size accepts a number of bytes, optionally suffixed by KiB or MiB.
func (p *parser) size(name string, def, min, max int64) int64 {
	v := strings.TrimSpace(p.getenv(name))
	if v == "" {
		return def
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(v, "MiB"):
		mult, v = 1<<20, strings.TrimSuffix(v, "MiB")
	case strings.HasSuffix(v, "KiB"):
		mult, v = 1<<10, strings.TrimSuffix(v, "KiB")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n*mult < min || n*mult > max {
		p.fail(name, fmt.Errorf("must be a size between %d and %d bytes", min, max))
		return def
	}
	return n * mult
}

func (p *parser) prefixes(name, def string) []netip.Prefix {
	v := p.getenv(name)
	if strings.TrimSpace(v) == "" {
		v = def
	}
	var out []netip.Prefix
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" || s == "none" {
			continue
		}
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			p.fail(name, errors.New("must be a comma-separated list of CIDR prefixes"))
			return nil
		}
		out = append(out, pfx.Masked())
	}
	return out
}

func identRe(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
