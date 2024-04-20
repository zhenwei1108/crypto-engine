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

type GeneralNames struct {
	GeneralNames []GeneralName
}

/*
	GeneralName ::= CHOICE {
	     otherName                       [0]     OtherName,
	     rfc822Name                      [1]     IA5String,
	     dNSName                         [2]     IA5String,
	     x400Address                     [3]     ORAddress,
	     directoryName                   [4]     Name,
	     ediPartyName                    [5]     EDIPartyName,
	     uniformResourceIdentifier       [6]     IA5String,
	     iPAddress                       [7]     OCTET STRING,
	     registeredID                    [8]     OBJECT IDENTIFIER }
*/
type GeneralName struct {
	otherName     asn1.RawValue         `asn1:"tag:0,optional"`
	rfc822Name    string                `asn1:"tag:1,optional"`
	dNSName       string                `asn1:"tag:2,optional"`
	x400Address   asn1.RawValue         `asn1:"tag:3,optional"`
	directoryName asn1.RawValue         `asn1:"tag:4,optional"`
	ediPartyName  asn1.RawValue         `asn1:"tag:5,optional"`
	URI           asn1.BitString        `asn1:"tag:6,optional"`
	iPAddress     asn1.BitString        `asn1:"tag:7,optional"`
	registeredID  asn1.ObjectIdentifier `asn1:"tag:8,optional"`
}

// pkcs8 的公钥
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type CrlDistPoints struct {
	CrlDistPoint DistributionPoint
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

type OtherName struct {
	id    asn1.ObjectIdentifier
	value asn1.RawValue
}

type ORAddress struct {
	BuiltInStandardAttributes struct {
		CountryName string `asn1:"printable"`
		// 其他标准属性...
	}
	BuiltInDomainDefinedAttributes []BuiltInDomainDefinedAttribute `asn1:"optional,tag:0"`
	ExtensionAttributes            []ExtensionAttribute            `asn1:"optional,tag:1"`
}

type BuiltInDomainDefinedAttribute struct {
	Type  string `asn1:"printable"`
	Value string `asn1:"printable"`
}

type ExtensionAttribute struct {
	ExtensionAttributeType  asn1.ObjectIdentifier `asn1:""`
	ExtensionAttributeValue asn1.RawValue         `asn1:""`
}

// 定义 EDIPartyName 结构体
type EDIPartyName struct {
	NameAssigner string `asn1:"optional,tag:0"`
	PartyName    string `asn1:"tag:1"`
}
