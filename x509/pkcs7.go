package x509

import (
	"encoding/asn1"
)

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Tag         asn1.RawValue
}

func BuildPkcs7Data(data []byte) (*ContentInfo, error) {
	marshal, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	return &ContentInfo{ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1},
		Tag: asn1.RawValue{Class: 2, Tag: 0, Bytes: marshal, IsCompound: true}}, nil

}
