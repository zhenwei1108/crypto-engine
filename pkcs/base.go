package pkcs

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

type IssuerAndSerialNumber struct {
	x500Name         asn1.RawValue "X500Name, 用于描述DN"
	certSerialNumber *big.Int
}

type attribute struct {
	attributeType  asn1.ObjectIdentifier
	attributeValue asn1.RawValue
}

// 主题标识符
type SubjectPublicKeyInfo struct {
	algorithm        pkix.AlgorithmIdentifier
	subjectPublicKey []byte
}
