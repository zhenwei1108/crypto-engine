package base

import (
	"crypto-engine/x509"
	"encoding/asn1"
)

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Tag         ContentType
}

type ContentType struct {
	x509.ASN1TaggedObject
}
