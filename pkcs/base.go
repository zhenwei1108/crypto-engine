package pkcs

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

type IssuerAndSerialNumber struct {
	X500Name         asn1.RawValue "X500Name, 用于描述DN"
	CertSerialNumber *big.Int
}

type Attribute struct {
	AttributeType  asn1.ObjectIdentifier
	AttributeValue asn1.RawValue
}

// 主题标识符
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey []byte
}

// 扩展项,cert\crl
type Extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool
	ExtnValue []byte
}
