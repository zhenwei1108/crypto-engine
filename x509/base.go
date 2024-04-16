package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

const (
	SHA256WithRSAOid  = "1.2.840.113549.1.1.11"
	SHA1WithRSAOid    = "1.2.840.113549.1.1.5"
	SM3WithSM2Oid     = "1.2.156.10197.1.501"
	SHA256WithWAPIOid = "1.2.156.11235.1.1.1"
)
const (
	ECCOid = "1.2.840.10045.2.1"
	SM2Oid = "1.2.156.10197.1.301"
	RSAOid = "1.2.840.113549.1.1.1"
)

type IssuerAndSerialNumber struct {
	X500Name         asn1.RawValue "X500Name, 用于描述DN"
	CertSerialNumber *big.Int
}

type Attribute struct {
	AttributeType  asn1.ObjectIdentifier
	AttributeValue asn1.RawValue
}

type DistributionPoint struct {
	DistributionPoint DistributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type DistributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

// pkcs8 的公钥
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type Name pkix.RDNSequence

// 0x0c = utf8
// 0x13 = printable
func (name Name) ToString() string {
	return pkix.RDNSequence(name).String()
}

type Version asn1.RawValue

func NewVersion(v int) (version Version) {
	realVersion, _ := asn1.Marshal(v)
	value := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		Bytes:      realVersion,
		IsCompound: true,
	}
	return Version(value)
}
