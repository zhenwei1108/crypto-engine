package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// GBT 20518-2018 信息安全技术 公钥基础设施 数字证书格式
// GMT-0015
type Certificate struct {
	TbsCertificate     TBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString `struct:"SM2Signature/[]byte" desc:"签名值"`
}

type TBSCertificate struct {
	Version              asn1.RawValue `asn1:"explicit,tag:0,default:0" version:"V1(0) V2(1) V3(2)"`
	SerialNumber         *big.Int
	Signature            pkix.AlgorithmIdentifier //签名算法
	Issuer               pkix.RDNSequence
	Validity             Validity
	Subject              pkix.RDNSequence
	SubjectPublicKeyInfo SubjectPublicKeyInfo //公钥信息
	IssuerUniqueID       asn1.RawValue        `asn1:"optional,tag:1"` // omitempty 指定此基础字段不被编码，   asn1:"optional“表示asn1不编码
	SubjectUniqueID      asn1.RawValue        `asn1:"optional,tag:2" desc:"如果出现，版本选择V3"`
	Extensions           []pkix.Extension     `asn1:"optional,explicit,tag:3" desc:"如果出现，版本选择V3"`
}

// 有效期
type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}
