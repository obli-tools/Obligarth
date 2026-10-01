package ade

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
)

// MachineInfo limits.
const (
	MachineInfoTTL      = 15 * time.Minute
	MaxMachineInfoBytes = 64 << 10
	maxChainDepth       = 5
)

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

// VerifyMachineInfo checks a CMS-signed MachineInfo: valid signature over
// the content, signer chained to one of roots (SHA-1 signatures accepted:
// Apple's device PKI predates SHA-2), and a plist with a UDID and a serial
// number in the expected formats.
func VerifyMachineInfo(der []byte, roots []*x509.Certificate, now time.Time) (*MachineInfo, error) {
	p7, err := pkcs7.Parse(der)
	if err != nil || len(p7.Signers) != 1 || len(p7.Content) == 0 {
		return nil, ErrMachineInfo
	}
	if err := p7.Verify(); err != nil {
		return nil, ErrMachineInfo
	}
	signer := p7.GetOnlySigner()
	if signer == nil || !chains(signer, p7.Certificates, roots, now) {
		return nil, ErrMachineInfo
	}
	var mi MachineInfo
	if err := plist.Unmarshal(p7.Content, &mi); err != nil {
		return nil, ErrMachineInfo
	}
	if !ids.ValidRawID(mi.UDID) || !SerialRe.MatchString(mi.Serial) {
		return nil, ErrMachineInfo
	}
	return &mi, nil
}

func validAt(c *x509.Certificate, now time.Time) bool {
	return !now.Before(c.NotBefore) && !now.After(c.NotAfter)
}

func signedBy(child, parent *x509.Certificate) bool {
	return bytes.Equal(child.RawIssuer, parent.RawSubject) &&
		parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
}

// chains walks from leaf to a root through the certificates of the CMS.
// x509.Verify cannot be used: it refuses SHA-1 signatures in a chain.
func chains(leaf *x509.Certificate, pool, roots []*x509.Certificate, now time.Time) bool {
	cur := leaf
	for depth := 0; depth < maxChainDepth; depth++ {
		if !validAt(cur, now) {
			return false
		}
		for _, r := range roots {
			if bytes.Equal(cur.Raw, r.Raw) {
				return depth > 0
			}
			if validAt(r, now) && signedBy(cur, r) {
				return true
			}
		}
		var next *x509.Certificate
		for _, c := range pool {
			if bytes.Equal(c.Raw, cur.Raw) || !c.BasicConstraintsValid || !c.IsCA {
				continue
			}
			if signedBy(cur, c) {
				next = c
				break
			}
		}
		if next == nil {
			return false
		}
		cur = next
	}
	return false
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
	mi, err := VerifyMachineInfo(raw, s.Roots, s.now())
	if err != nil {
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
