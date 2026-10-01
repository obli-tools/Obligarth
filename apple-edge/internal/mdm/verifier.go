package mdm

import (
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/smallstep/pkcs7"

	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
	"github.com/MeeJay/Obligarth/apple-edge/internal/tenant"
)

// Cache of issued certificates.
const (
	certCacheTTL  = 60 * time.Second
	certCacheSize = 100000
	eventInterval = time.Hour
)

type issuedInfo struct {
	store.IssuedCert
}

// Verifier checks a device identity against the tenant named in the URL:
// chain to an active or verify_only CA of that tenant only, client
// authentication usage, validity, and registration in issued_certs for that
// tenant without revocation. It implements http/mdm.CertVerifier.
type Verifier struct {
	db      *sql.DB
	reg     *tenant.Registry
	out     *outbox.Writer
	logger  *obs.Logger
	metrics *obs.Metrics
	now     func() time.Time
	cache   *lru
	events  *dedup
}

// NewVerifier returns the tenant verifier.
func NewVerifier(db *sql.DB, reg *tenant.Registry, out *outbox.Writer, logger *obs.Logger, m *obs.Metrics) *Verifier {
	return &Verifier{db: db, reg: reg, out: out, logger: logger.With("component", "verifier"), metrics: m, now: time.Now,
		cache: newLRU(certCacheSize, certCacheTTL), events: newDedup(eventInterval)}
}

var (
	errNoCert      = errors.New("no device certificate")
	errChain       = errors.New("certificate does not chain to a CA of the URL tenant")
	errUnknownCert = errors.New("certificate not issued to this tenant")
	errRevoked     = errors.New("certificate revoked")
)

// Evict drops a fingerprint from the cache (revocation on this replica).
func (v *Verifier) Evict(sha string) { v.cache.remove(sha) }

// Verify implements http/mdm.CertVerifier.
func (v *Verifier) Verify(ctx context.Context, cert *x509.Certificate) error {
	st := stateFrom(ctx)
	if st == nil || st.tenant == nil {
		return errNoState
	}
	st.stage = "refused"
	t := st.tenant
	if cert == nil {
		return errNoCert
	}
	sum := sha256.Sum256(cert.Raw)
	sha := hex.EncodeToString(sum[:])
	now := v.now()
	if _, err := cert.Verify(x509.VerifyOptions{Roots: t.Roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		v.classifyChainError(ctx, t, cert, sha, err, now)
		return errChain
	}
	ic, err := v.lookup(ctx, sha)
	if err != nil {
		return err
	}
	if ic == nil || ic.Tenant != t.Key {
		v.metrics.SecurityEvents.Inc(t.Key, "unknown_certificate")
		return errUnknownCert
	}
	if ic.Revoked {
		v.emitOnce(ctx, sha, "security.identity_revoked", outbox.T(t.Key, "security.identity_revoked", map[string]any{"cert_sha256": sha}))
		return errRevoked
	}
	st.stage, st.certSHA, st.issued = "verified", sha, &issuedInfo{*ic}
	return nil
}

func (v *Verifier) lookup(ctx context.Context, sha string) (*store.IssuedCert, error) {
	if ic, ok := v.cache.get(sha); ok {
		return ic, nil
	}
	ic, err := store.LookupIssuedCert(ctx, v.db, sha)
	if err != nil {
		return nil, err
	}
	if ic != nil {
		v.cache.put(sha, ic)
	}
	return ic, nil
}

// classifyChainError emits the security event matching a refused chain:
// expired identity of this tenant, or valid identity of another tenant.
func (v *Verifier) classifyChainError(ctx context.Context, t *tenant.Tenant, cert *x509.Certificate, sha string, err error, now time.Time) {
	var inv x509.CertificateInvalidError
	if errors.As(err, &inv) && inv.Reason == x509.Expired {
		if _, err2 := cert.Verify(x509.VerifyOptions{Roots: t.Roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: cert.NotAfter.Add(-time.Minute)}); err2 == nil {
			v.emitOnce(ctx, sha, "security.identity_expired", outbox.T(t.Key, "security.identity_expired", map[string]any{
				"cert_sha256": sha, "not_after": cert.NotAfter.UTC().Format(time.RFC3339)}))
			return
		}
	}
	for _, ou := range cert.Issuer.OrganizationalUnit {
		if !ids.ValidTenantKey(ou) || ou == t.Key {
			continue
		}
		other := v.reg.Get(ou)
		if other == nil || other.Roots == nil {
			continue
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: other.Roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err == nil {
			v.emitOnce(ctx, sha, "security.foreign_certificate", outbox.P("security.foreign_certificate", map[string]any{
				"url_tenant": t.Key, "issuer_tenant": other.Key}))
			return
		}
	}
	v.metrics.SecurityEvents.Inc(t.Key, "untrusted_certificate")
}

// ReportSignatureFailure is called when Mdm-Signature verification failed.
// The CMS library checks the signing time against the signer's validity
// before the signature itself, so an expired identity never reaches the
// verifier: this recognises a genuine signature by an expired identity of
// the URL tenant and reports security.identity_expired.
func (v *Verifier) ReportSignatureFailure(ctx context.Context, t *tenant.Tenant, header string, body []byte) {
	cert := expiredSigner(header, body, v.now())
	if cert == nil || t.Roots == nil {
		return
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: t.Roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: cert.NotAfter.Add(-time.Minute)}); err != nil {
		return
	}
	sum := sha256.Sum256(cert.Raw)
	sha := hex.EncodeToString(sum[:])
	if ic, err := v.lookup(ctx, sha); err != nil || ic == nil || ic.Tenant != t.Key {
		return
	}
	v.emitOnce(ctx, sha, "security.identity_expired", outbox.T(t.Key, "security.identity_expired", map[string]any{
		"cert_sha256": sha, "not_after": cert.NotAfter.UTC().Format(time.RFC3339)}))
}

// expiredSigner returns the signer of an Mdm-Signature whose only defect is
// a signing time after the expiry of the signer's certificate, the
// signature itself being verified here.
func expiredSigner(header string, body []byte, now time.Time) *x509.Certificate {
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil
	}
	p7, err := pkcs7.Parse(raw)
	if err != nil || len(p7.Signers) != 1 {
		return nil
	}
	p7.Content = body
	var ste *pkcs7.SigningTimeNotValidError
	if err := p7.Verify(); !errors.As(err, &ste) || !ste.SigningTime.After(ste.NotAfter) {
		return nil // valid, or refused for another reason (digest mismatch...)
	}
	signer := p7.GetOnlySigner()
	if signer == nil || !now.After(signer.NotAfter) {
		return nil
	}
	si := p7.Signers[0]
	alg := signatureAlgorithm(si.DigestEncryptionAlgorithm.Algorithm, si.DigestAlgorithm.Algorithm)
	if alg == x509.UnknownSignatureAlgorithm || len(si.AuthenticatedAttributes) == 0 {
		return nil
	}
	// DER of the authenticated attributes as signed: a SET OF in the
	// received order (what the library verifies).
	attrs, err := asn1.Marshal(si.AuthenticatedAttributes)
	if err != nil || len(attrs) == 0 {
		return nil
	}
	attrs[0] = 0x31
	if signer.CheckSignature(alg, attrs, si.EncryptedDigest) != nil {
		return nil
	}
	return signer
}

// signatureAlgorithm mirrors the mapping of the CMS library (devices and
// simulators commonly sign with SHA-1, accepted for data signatures).
func signatureAlgorithm(enc, digest asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	rsa := enc.Equal(pkcs7.OIDEncryptionAlgorithmRSA) || enc.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA1) ||
		enc.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA256) || enc.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA384) ||
		enc.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA512)
	switch {
	case rsa && digest.Equal(pkcs7.OIDDigestAlgorithmSHA1):
		return x509.SHA1WithRSA
	case rsa && digest.Equal(pkcs7.OIDDigestAlgorithmSHA256):
		return x509.SHA256WithRSA
	case rsa && digest.Equal(pkcs7.OIDDigestAlgorithmSHA384):
		return x509.SHA384WithRSA
	case rsa && digest.Equal(pkcs7.OIDDigestAlgorithmSHA512):
		return x509.SHA512WithRSA
	case enc.Equal(pkcs7.OIDDigestAlgorithmECDSASHA256):
		return x509.ECDSAWithSHA256
	case enc.Equal(pkcs7.OIDDigestAlgorithmECDSASHA384):
		return x509.ECDSAWithSHA384
	case enc.Equal(pkcs7.OIDDigestAlgorithmECDSASHA512):
		return x509.ECDSAWithSHA512
	}
	return x509.UnknownSignatureAlgorithm
}

func (v *Verifier) emitOnce(ctx context.Context, sha, typ string, ev outbox.Event) {
	tenantLabel := ev.Tenant
	if tenantLabel == "" {
		tenantLabel = "platform"
	}
	v.metrics.SecurityEvents.Inc(tenantLabel, typ)
	if !v.events.first(typ+"/"+sha, v.now()) {
		return
	}
	if err := v.out.Emit(context.WithoutCancel(ctx), ev); err != nil {
		v.logger.Error("msg", "security event", "err", err)
	}
}

// lru is a small LRU with a time to live.
type lru struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	ll    *list.List
	items map[string]*list.Element
	now   func() time.Time
}

type lruEntry struct {
	key     string
	value   *store.IssuedCert
	expires time.Time
}

func newLRU(max int, ttl time.Duration) *lru {
	return &lru{max: max, ttl: ttl, ll: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

func (c *lru) get(key string) (*store.IssuedCert, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*lruEntry)
	if c.now().After(e.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return e.value, true
}

func (c *lru) put(key string, v *store.IssuedCert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.Remove(el)
	}
	c.items[key] = c.ll.PushFront(&lruEntry{key: key, value: v, expires: c.now().Add(c.ttl)})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.items, last.Value.(*lruEntry).key)
	}
}

func (c *lru) remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.Remove(el)
		delete(c.items, key)
	}
}

// dedup lets an event through at most once per key and interval.
type dedup struct {
	mu       sync.Mutex
	interval time.Duration
	last     map[string]time.Time
}

func newDedup(interval time.Duration) *dedup {
	return &dedup{interval: interval, last: map[string]time.Time{}}
}

func (d *dedup) first(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.last[key]; ok && now.Sub(t) < d.interval {
		return false
	}
	if len(d.last) > 100000 {
		for k, t := range d.last {
			if now.Sub(t) >= d.interval {
				delete(d.last, k)
			}
		}
	}
	d.last[key] = now
	return true
}
