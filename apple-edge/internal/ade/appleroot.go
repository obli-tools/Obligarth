package ade

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// AppleRootCASHA256 is the SHA-256 fingerprint of "Apple Root CA" (Apple
// Inc., 2006-2035) published by Apple on apple.com/certificateauthority and
// in its lists of trusted root certificates. MachineInfo signatures chain
// to this root.
const AppleRootCASHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"

// AppleIPhoneDeviceCASPKISHA256 pins the public key (SHA-256 of the DER
// SubjectPublicKeyInfo) of "Apple iPhone Device CA" (C=US, O=Apple Inc.,
// OU=Apple iPhone), the Apple CA that issues the device identity
// certificates signing MachineInfo. Apple publishes its certificate
// (SHA-256 76f27d00e1333bc88de0e2916c38c9a7f2b75774c25a794c092a80e3c4c66cce,
// RSA 1024, SHA-1, valid 2007-2014) in its over-the-air enrollment guide,
// which asks to check that a device certificate is issued by this CA and
// to ignore the validity dates. It is issued by "Apple iPhone
// Certification Authority" (SHA-256
// e4e2936d3c076ec4aea8ac37277524950ca005894b39bba2d347fa33155ae5fa, valid
// 2007-2022), itself issued by Apple Root CA: both intermediates are
// expired and still sign current device identities.
const AppleIPhoneDeviceCASPKISHA256 = "13686ec675f9fd26a123adb17b5533f593cf451edd6105ae39b748277a3922e5"

// appleDeviceCAPins lists, by public key, the Apple CAs allowed to issue
// the signer of a MachineInfo. A certificate issued under Apple Root CA
// by any other CA (developer, push, application integration...) is
// refused.
//
// Rotation: when Apple introduces another device CA (a genuine device
// refused with "issuer not pinned", or a publication by Apple), take its
// certificate from Apple and from a genuine MachineInfo, check that both
// match and chain to Apple Root CA, add the SHA-256 of its
// SubjectPublicKeyInfo here with its name, and release. Keep a pin as long
// as devices may present identities issued under it (validity dates are
// ignored): remove it when Apple retires the CA, or at once by a release
// if it is compromised.
var appleDeviceCAPins = map[string]string{
	AppleIPhoneDeviceCASPKISHA256: "Apple iPhone Device CA",
}

// appleRootCAPEM is the public certificate of Apple Root CA, kept as a Go
// constant (certificate files are not versioned).
const appleRootCAPEM = `-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMK
QXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNV
BAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYD
VQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg++FAJ039B
qJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N
8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5Dtle
HNbLPbU6rfQPDgCSC7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGIL
EINBhzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNV
HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3R01/
CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAEggEIMIIBBDCCAQAG
CSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2Ev
MIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBh
cnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRl
cm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBcNplMLXi37Yyb
3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOL
UyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+
IjXKJdXZD9Zr1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltk
wGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPI
S4AXUKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
`

// AppleRootCA returns Apple Root CA after checking its fingerprint.
func AppleRootCA() (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(appleRootCAPEM))
	if blk == nil {
		return nil, fmt.Errorf("ade: Apple root certificate unreadable")
	}
	sum := sha256.Sum256(blk.Bytes)
	if hex.EncodeToString(sum[:]) != AppleRootCASHA256 {
		return nil, fmt.Errorf("ade: Apple root certificate fingerprint mismatch")
	}
	return x509.ParseCertificate(blk.Bytes)
}
