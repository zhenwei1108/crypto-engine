package base

import (
	"crypto-engine/x500"
	"encoding/asn1"
)

type ContentInfo struct {
	contentType asn1.ObjectIdentifier
	tag         ContentType
}

type ContentType struct {
	x500.ASN1TaggedObject
}

func (ContentInfo) Wrapper(data []byte) x500.ASN1Object {
	var contentInfo ContentInfo

	return contentInfo
}
func (ContentInfo) UnWrapper(object x500.ASN1Object) []byte {
	return nil
}
