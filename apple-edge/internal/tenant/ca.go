package tenant

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/MeeJay/Obligarth/apple-edge/internal/scep"
)

// CAKeyBits is the size of a tenant CA key.
const CAKeyBits = 3072

// NewCA generates the issuing CA of a tenant: RSA 3072, SHA-256, CA:true
// with pathlen 0. The same key pair decrypts the SCEP envelopes, hence
// keyEncipherment.
func NewCA(key string, years int, now time.Time) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, CAKeyBits)
	if err != nil {
		return nil, nil, err
	}
	serial, err := scep.RandomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "Obligarth Device CA " + key,
			OrganizationalUnit: []string{key},
			Organization:       []string{"Obligarth"},
		},
		NotBefore:             now.Add(-time.Hour).UTC(),
		NotAfter:              now.AddDate(years, 0, 0).UTC(),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}
