package pkcs

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// GBT 20518-2018 信息安全技术 公钥基础设施 数字证书格式
// GMT-0015
type Certificate struct {
	TbsCertificate     TBSCertificate `struct:"TBSCertificate"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     []byte `struct:"SM2Signature/[]byte" desc:"签名值"`
}

type TBSCertificate struct {
	Version              asn1.RawValue `tag:"0" default:"V1" version:"V1(0) V2(1) V3(2)"`
	SerialNumber         *big.Int
	Signature            pkix.AlgorithmIdentifier //签名算法
	Issuer               pkix.Name
	Validity             Validity `struct:"Validity"`
	Subject              pkix.Name
	SubjectPublicKeyInfo SubjectPublicKeyInfo `struct:"SubjectPublicKeyInfo"` //公钥信息
	IssuerUniqueID       asn1.RawValue        `tag:"1" optional:"true" desc:"如果出现，版本选择V2或V3"`
	SubjectUniqueID      asn1.RawValue        `tag:"2" optional:"true" desc:"如果出现，版本选择V2或V3"`
	// 为什么不可以 []Extension
	Extensions []Extension `struct:"Extension" tag:"3"  optional:"true" desc:"如果出现，版本选择V3"`
}

// 有效期
type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// 扩展项
type Extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool
	ExtnValue []byte
}
