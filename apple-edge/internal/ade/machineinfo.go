package ade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/crypto/cmssig"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/plistlimit"
)

// MachineInfo limits.
const (
	MachineInfoTTL      = 15 * time.Minute
	MaxMachineInfoBytes = 64 << 10
	maxChainDepth       = 5
	maxCertificates     = 8 // a genuine MachineInfo carries the leaf and two intermediates
)

// machineInfoPlist bounds the signed content (a flat dictionary).
var machineInfoPlist = plistlimit.Limits{MaxDepth: 8, MaxElements: 512}

// SerialRe is the format accepted for serial numbers.
var SerialRe = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// ErrMachineInfo is returned for a MachineInfo whose signature, chain or
// content is not acceptable.
var ErrMachineInfo = errors.New("ade: MachineInfo refused")

// MachineInfo is the verified content of the x-apple-aspen-deviceinfo header.
type MachineInfo struct {
	UDID      string `plist:"UDID"`
	Serial    string `plist:"SERIAL"`
	Product   string `plist:"PRODUCT"`
	Version   string `plist:"VERSION"`
	OSVersion string `plist:"OS_VERSION"`
	Language  string `plist:"LANGUAGE"`
}

// Trust anchors MachineInfo signatures: the roots, and the public keys of
// the CAs allowed to issue the signer (device identity CAs).
type Trust struct {
	roots []*x509.Certificate
	pins  map[string]string // SHA-256 of the SubjectPublicKeyInfo (hex) -> name
}

// AppleTrust returns the trust of production: Apple Root CA, checked
// against its fingerprint, and the pinned Apple device CAs.
func AppleTrust() (*Trust, error) {
	root, err := AppleRootCA()
	if err != nil {
		return nil, err
	}
	return &Trust{roots: []*x509.Certificate{root}, pins: maps.Clone(appleDeviceCAPins)}, nil
}

// WithTestPKI returns a copy of t that also trusts a test PKI (development
// only): its self-signed CA certificates as roots, its other CA
// certificates as pinned device CAs.
func (t *Trust) WithTestPKI(certs []*x509.Certificate) (*Trust, error) {
	n := &Trust{roots: slices.Clone(t.roots), pins: map[string]string{}}
	maps.Copy(n.pins, t.pins)
	pinned := 0
	for _, c := range certs {
		switch {
		case !caCert(c):
			return nil, fmt.Errorf("ade: %q is not a CA certificate", c.Subject.CommonName)
		case signedBy(c, c):
			n.roots = append(n.roots, c)
		default:
			n.pins[SPKISHA256(c)] = c.Subject.CommonName
			pinned++
		}
	}
	if pinned == 0 {
		return nil, errors.New("ade: no device CA to pin (a test PKI needs a root and the CA issuing the device identities)")
	}
	return n, nil
}

// SPKISHA256 returns the SHA-256 (hex) of the DER SubjectPublicKeyInfo of
// c, the fingerprint of its public key.
func SPKISHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// Reasons of a refusal (fixed texts, safe for the logs).
var (
	errMIFormat  = fmt.Errorf("%w: not a CMS SignedData of a single signer", ErrMachineInfo)
	errMISig     = fmt.Errorf("%w: signature", ErrMachineInfo)
	errMIUsage   = fmt.Errorf("%w: signer is not a device identity", ErrMachineInfo)
	errMIIssuer  = fmt.Errorf("%w: issuer not pinned", ErrMachineInfo)
	errMIChain   = fmt.Errorf("%w: no chain to a root", ErrMachineInfo)
	errMIContent = fmt.Errorf("%w: content", ErrMachineInfo)
)

// VerifyMachineInfo checks a CMS-signed MachineInfo: a single signer whose
// signature covers the content; a signer with the usages of a device
// identity, issued by a pinned device CA whose chain reaches a root
// through the certificates of the CMS; then a bounded plist with a UDID
// and a serial number in the expected formats. Validity dates are ignored,
// as Apple asks for device certificates: the intermediates of its device
// PKI expired in 2014 and 2022 and still sign current identities, in
// SHA-1, which x509.Verify refuses. Errors wrap ErrMachineInfo.
func VerifyMachineInfo(der []byte, trust *Trust) (*MachineInfo, error) {
	p7, err := pkcs7.Parse(der)
	if err != nil || len(p7.Signers) != 1 || len(p7.Content) == 0 || len(p7.Certificates) > maxCertificates {
		return nil, errMIFormat
	}
	leaf, err := cmssig.VerifySigner(p7)
	if err != nil {
		return nil, errMISig
	}
	if err := trust.verifyDevice(leaf, p7.Certificates); err != nil {
		return nil, err
	}
	if _, err := plistlimit.Check(context.Background(), p7.Content, machineInfoPlist); err != nil {
		return nil, errMIContent
	}
	var mi MachineInfo
	if err := plist.Unmarshal(p7.Content, &mi); err != nil {
		return nil, errMIContent
	}
	if !ids.ValidRawID(mi.UDID) || !SerialRe.MatchString(mi.Serial) {
		return nil, errMIContent
	}
	return &mi, nil
}

// verifyDevice accepts a leaf that is a device identity (not a CA, digital
// signature, client authentication), issued by a pinned CA, whose chain
// reaches a root through bag. Only signatures are checked (SHA-1
// accepted), never validity dates; the pinned key itself verifies the
// leaf, whatever the rest of the certificate carrying it.
func (t *Trust) verifyDevice(leaf *x509.Certificate, bag []*x509.Certificate) error {
	if t == nil {
		return errMIChain
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return errMIUsage
	}
	var cur *x509.Certificate
	for _, c := range bag {
		if _, pinned := t.pins[SPKISHA256(c)]; pinned && caCert(c) && signedBy(leaf, c) {
			cur = c
			break
		}
	}
	if cur == nil {
		return errMIIssuer
	}
	for range maxChainDepth {
		for _, r := range t.roots {
			if signedBy(cur, r) {
				return nil
			}
		}
		var next *x509.Certificate
		for _, c := range bag {
			if c != cur && caCert(c) && signedBy(cur, c) {
				next = c
				break
			}
		}
		if next == nil {
			return errMIChain
		}
		cur = next
	}
	return errMIChain
}

// caCert reports whether c may issue certificates.
func caCert(c *x509.Certificate) bool {
	return c.BasicConstraintsValid && c.IsCA && (c.KeyUsage == 0 || c.KeyUsage&x509.KeyUsageCertSign != 0)
}

func signedBy(child, parent *x509.Certificate) bool {
	return bytes.Equal(child.RawIssuer, parent.RawSubject) &&
		parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
}

// CheckResult is the answer of POST .../machine-info/verify.
type CheckResult struct {
	MachineInfoID  string    `json:"machine_info_id"`
	UDID           string    `json:"udid"`
	Serial         string    `json:"serial"`
	Product        string    `json:"product"`
	OSVersion      string    `json:"os_version"`
	Version        string    `json:"version"`
	SerialInTenant bool      `json:"serial_in_tenant"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// VerifyMachineInfo verifies the header value (base64 CMS) sent by a device
// in the Setup Assistant, checks that its serial number is an ADE device of
// the tenant, and records the check for 15 minutes: a SCEP challenge
// created with its id is bound to the verified UDID and serial number.
func (s *Service) VerifyMachineInfo(ctx context.Context, tenant, headerValue string) (CheckResult, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(headerValue), ""))
	if err != nil || len(raw) == 0 || len(raw) > MaxMachineInfoBytes {
		return CheckResult{}, apierr.BadRequest("machine_info must be the base64 value of the x-apple-aspen-deviceinfo header")
	}
	mi, err := VerifyMachineInfo(raw, s.Trust)
	if err != nil {
		s.Logger.Info("msg", "MachineInfo refused", "component", "ade", "tenant", tenant, "err", err)
		return CheckResult{}, apierr.New(400, "invalid_machine_info", "MachineInfo signature, chain or content refused")
	}
	var tokenID sql.NullString
	err = s.DB.QueryRowContext(ctx, `
SELECT d.token_id::text FROM apple_edge.ade_devices d JOIN apple_edge.ade_tokens t ON t.id = d.token_id
 WHERE d.tenant_key = $1 AND d.serial = $2 AND t.tenant_key = $1 AND t.state <> 'removed'
 ORDER BY d.updated_at DESC LIMIT 1`, tenant, mi.Serial).Scan(&tokenID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return CheckResult{}, err
	}
	res := CheckResult{MachineInfoID: ids.NewUUID(), UDID: mi.UDID, Serial: mi.Serial, Product: mi.Product,
		OSVersion: mi.OSVersion, Version: mi.Version, SerialInTenant: tokenID.Valid}
	err = s.DB.QueryRowContext(ctx, `
INSERT INTO apple_edge.machine_info_checks (id, tenant_key, udid, serial, token_id, expires_at)
VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
RETURNING expires_at`, res.MachineInfoID, tenant, mi.UDID, mi.Serial, tokenID, MachineInfoTTL.Seconds()).Scan(&res.ExpiresAt)
	if err != nil {
		return CheckResult{}, err
	}
	res.ExpiresAt = res.ExpiresAt.UTC()
	return res, nil
}

// Check is a MachineInfo check usable for a challenge.
type Check struct {
	UDID, Serial string
}

// MachineInfoCheck returns an unexpired check of the tenant.
func MachineInfoCheck(ctx context.Context, db *sql.DB, tenant, id string) (*Check, error) {
	var c Check
	err := db.QueryRowContext(ctx, `
SELECT udid, serial FROM apple_edge.machine_info_checks
 WHERE id = $1 AND tenant_key = $2 AND expires_at > now()`, id, tenant).Scan(&c.UDID, &c.Serial)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// PurgeMachineInfoChecks deletes checks expired for more than a day that
// no issued identity relies on (its proof stays derivable).
func PurgeMachineInfoChecks(ctx context.Context, db *sql.DB) (int64, error) {
	res, err := db.ExecContext(ctx, `
DELETE FROM apple_edge.machine_info_checks m
 WHERE m.expires_at < now() - interval '24 hours'
   AND NOT EXISTS (SELECT 1 FROM apple_edge.scep_challenges c JOIN apple_edge.issued_certs i ON i.challenge_id = c.id
                    WHERE c.machine_info_id = m.id)`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
