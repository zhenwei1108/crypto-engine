package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

const (
	SHA256WithRSA  = "1.2.840.113549.1.1.11"
	SHA1WithRSA    = "1.2.840.113549.1.1.5"
	SM3WithSM2     = "1.2.156.10197.1.501"
	SHA256WithWapi = "1.2.156.11235.1.1.1"
)
const (
	ECC = "1.2.840.10045.2.1"
)

type IssuerAndSerialNumber struct {
	X500Name         asn1.RawValue "X500Name, 用于描述DN"
	CertSerialNumber *big.Int
}

type Attribute struct {
	AttributeType  asn1.ObjectIdentifier
	AttributeValue asn1.RawValue
}

// pkcs8 的公钥
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}
