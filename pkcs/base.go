package pkcs

import (
	"encoding/asn1"
	"math/big"
)

type IssuerAndSerialNumber struct {
	x500Name         asn1.RawValue "X500Name, 用于描述DN"
	certSerialNumber *big.Int
}
