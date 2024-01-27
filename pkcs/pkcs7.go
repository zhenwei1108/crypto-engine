package pkcs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

const (
	Data = iota
	SignedData
)

type contentTypeOid struct {
	oid asn1.ObjectIdentifier
}

type contentOid struct {
	data, signedData, envelopedData, signedAndEnvelopedData, encryptedData, keyAgreementInfo asn1.ObjectIdentifier
}

// 常量必须是基本类型
var (
	//国密
	GMContentOid = contentOid{data: asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1},
		signedData:             asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2},
		envelopedData:          asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 3},
		signedAndEnvelopedData: asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 4},
		encryptedData:          asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 5},
		keyAgreementInfo:       asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 6}}

	//PKCS
	PKCSContentOid = contentOid{data: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1},
		signedData:             asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		envelopedData:          asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3},
		signedAndEnvelopedData: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4},
		encryptedData:          asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5},
		keyAgreementInfo:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}}
)

/*
《GMT-0010 SM2 密码算法加密签名消息语法规范》
*/
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type signedData struct {
	version          int
	digestAlgorithms []pkix.AlgorithmIdentifier "摘要算法标识"
	contentInfo      ContentInfo                "原文"
	certificates     []x509.Certificate         "证书/证书链"
	crls             []asn1.RawValue            "吊销列表"
	signerInfos      []SignerInfo               "签名信息"
}

type SignerInfo struct {
	version                   int                      "版本"
	issuerAndSerialNumber     IssuerAndSerialNumber    "颁发者信息"
	digestAlgorithm           pkix.AlgorithmIdentifier "摘要算法"
	attributes                []Attribute              "optional,tag:0, 签名者属性"
	digestEncryptionAlgorithm pkix.AlgorithmIdentifier "签名算法"
	encryptDigest             asn1.RawValue            "签名值,SM2时是 SM2Signature"
	unauthenticatedAttributes []Attribute              "optional,tag:1"
}

func BuildPkcs7Data(resource []byte, isGM bool) (*ContentInfo, error) {
	marshal, err := asn1.Marshal(resource)
	if err != nil {
		return nil, err
	}
	contentOid := PKCSContentOid.data
	if isGM {
		contentOid = GMContentOid.data
	}
	return &ContentInfo{ContentType: contentOid,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: marshal, IsCompound: true}}, nil
}

func BuildPkcs7SignedData(resource []byte, cert []byte) (*ContentInfo, error) {
	signedData, _ := asn1.Marshal(resource)
	asn1.Marshal(signedData)
	return nil, nil
}
