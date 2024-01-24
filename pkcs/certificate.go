package pkcs

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// GBT 20518-2018 信息安全技术 公钥基础设施 数字证书格式
// GMT-0015
type Certificate struct {
	tbsCertificate     asn1.RawValue `struct:"TBSCertificate"`
	signatureAlgorithm pkix.AlgorithmIdentifier
	signatureValue     []byte
}

type TBSCertificate struct {
	version              asn1.RawValue `tag:"0" default:"V1" version:"V1(0) V2(1) V3(2)"`
	serialNumber         big.Int
	signature            pkix.AlgorithmIdentifier
	issuer               pkix.Name
	validity             asn1.RawValue `struct:"Validity"`
	subject              pkix.Name
	subjectPublicKeyInfo asn1.RawValue   `struct:"SubjectPublicKeyInfo"`
	issuerUniqueID       []byte          `tag:"1" optional:"true" desc:"如果出现，版本选择V2或V3"`
	subjectUniqueID      []byte          `tag:"2" optional:"true" desc:"如果出现，版本选择V2或V3"`
	extensions           []asn1.RawValue `tag:"3"  optional:"true" desc:"如果出现，版本选择V3"`
}

type Validity struct {
}

type SubjectPublicKeyInfo struct {
}
