// Package cmssig verifies the signer of a CMS SignedData without the time
// checks of the CMS library, which refuses a signing time outside the
// validity of the signer before checking the signature. The callers judge
// validity themselves: Apple asks to ignore the validity dates of device
// identity certificates, and an expired MDM identity is reported, never
// trusted.
package cmssig

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"hash"

	"github.com/smallstep/pkcs7"
)

// Errors of VerifySigner (besides the error of the signature check).
var (
	ErrSigner     = errors.New("cmssig: exactly one signer with its certificate expected")
	ErrAlgorithm  = errors.New("cmssig: unsupported signature algorithm")
	ErrAttributes = errors.New("cmssig: invalid signed attributes")
	ErrDigest     = errors.New("cmssig: message digest mismatch")
)

// SignatureAlgorithm maps the algorithms of a SignerInfo onto an x509
// signature algorithm, as the CMS library does (devices and simulators
// commonly sign with SHA-1, accepted for data signatures).
func SignatureAlgorithm(enc, digest asn1.ObjectIdentifier) x509.SignatureAlgorithm {
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

func newHash(digest asn1.ObjectIdentifier) hash.Hash {
	switch {
	case digest.Equal(pkcs7.OIDDigestAlgorithmSHA1):
		return sha1.New()
	case digest.Equal(pkcs7.OIDDigestAlgorithmSHA256):
		return sha256.New()
	case digest.Equal(pkcs7.OIDDigestAlgorithmSHA384):
		return sha512.New384()
	case digest.Equal(pkcs7.OIDDigestAlgorithmSHA512):
		return sha512.New()
	}
	return nil
}

// SignedAttributes returns the DER of the signed attributes of the only
// signer as they were signed: a SET OF in the received order (what the
// CMS library verifies too).
func SignedAttributes(p7 *pkcs7.PKCS7) ([]byte, error) {
	if len(p7.Signers) != 1 || len(p7.Signers[0].AuthenticatedAttributes) == 0 {
		return nil, ErrAttributes
	}
	attrs, err := asn1.Marshal(p7.Signers[0].AuthenticatedAttributes)
	if err != nil || len(attrs) == 0 {
		return nil, ErrAttributes
	}
	attrs[0] = 0x31
	return attrs, nil
}

// VerifySigner checks the only signer of p7: its certificate is in the
// CMS and its signature covers the content, or the signed attributes,
// whose message digest must then match the content and whose content type
// must be data. No signing time nor validity date is checked.
func VerifySigner(p7 *pkcs7.PKCS7) (*x509.Certificate, error) {
	if p7 == nil || len(p7.Signers) != 1 {
		return nil, ErrSigner
	}
	cert := p7.GetOnlySigner()
	if cert == nil {
		return nil, ErrSigner
	}
	si := p7.Signers[0]
	alg := SignatureAlgorithm(si.DigestEncryptionAlgorithm.Algorithm, si.DigestAlgorithm.Algorithm)
	h := newHash(si.DigestAlgorithm.Algorithm)
	if alg == x509.UnknownSignatureAlgorithm || h == nil {
		return nil, ErrAlgorithm
	}
	signed := p7.Content
	if len(si.AuthenticatedAttributes) > 0 {
		var digest []byte
		var contentType asn1.ObjectIdentifier
		if p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeMessageDigest, &digest) != nil ||
			p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeContentType, &contentType) != nil ||
			!contentType.Equal(pkcs7.OIDData) {
			return nil, ErrAttributes
		}
		h.Write(p7.Content)
		if subtle.ConstantTimeCompare(digest, h.Sum(nil)) != 1 {
			return nil, ErrDigest
		}
		attrs, err := SignedAttributes(p7)
		if err != nil {
			return nil, err
		}
		signed = attrs
	}
	if err := cert.CheckSignature(alg, signed, si.EncryptedDigest); err != nil {
		return nil, err
	}
	return cert, nil
}
