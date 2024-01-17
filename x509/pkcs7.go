package x509

import (
	"encoding/asn1"
	"errors"
)

/*
《GMT-0010 SM2 密码算法加密签名消息语法规范》
*/
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

const (
	ContentData = iota
	ContentSignedData
)

type contentTypeOid struct {
	oid asn1.ObjectIdentifier
}

var ()

type contentOid struct {
	data, signedData, envelopedData, signedAndEnvelopedData, encryptedData, keyAgreementInfo asn1.ObjectIdentifier
}

// 常量必须是基本类型
var (
	//国密
	GMContentTypeOid = contentTypeOid{asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2}}

	GMContentOid = contentOid{data: asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1},
		signedData:             asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2},
		envelopedData:          asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 3},
		signedAndEnvelopedData: asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 4},
		encryptedData:          asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 5},
		keyAgreementInfo:       asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 6}}

	//PKCS
	PKCSContentTypeOid = contentTypeOid{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7}}

	PKCSContentOid = contentOid{data: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1},
		signedData:             asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		envelopedData:          asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3},
		signedAndEnvelopedData: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4},
		encryptedData:          asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5},
		keyAgreementInfo:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}}
)

func BuildPkcs7Data(data []byte) (*ContentInfo, error) {
	marshal, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	return &ContentInfo{ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1},
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: marshal, IsCompound: true}}, nil
}

func BuildPkcs7(content int, data []byte) (contentInfo *ContentInfo, err error) {
	var contentValue []byte
	switch content {
	case ContentData:
		contentValue, err := asn1.Marshal(data)
		if err != nil {
			return nil, err
		}
		break
	case ContentSignedData:
		return nil, err
	default:
		return nil, errors.New("not support type" + string(rune(content)))

	}

	return &ContentInfo{ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1},
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: contentValue, IsCompound: true}}, nil
}
