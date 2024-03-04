package example

import (
	"crypto-engine/pkcs"
	rand2 "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func Test_code_cert(t *testing.T) {
	var cert = "MIIB8zCCAZmgAwIBAgIKAKjKSNY55JbBcTAKBggqhkjOPQQDAjBCMSowKAYDVQQDDCFNaWRlYSBHcm91cCBNYXR0ZXIgUEFJIEcxIEkxIFByb2QxFDASBgorBgEEAYKifAIBEwQxMThDMCAXDTIzMTAyNDE1NTM0MVoYDzIwODcwODI0MTU1OTU5WjBXMSkwJwYDVQQDDCBEOUIyQUFFODcxQjUzRUU2NTYzMjQyOTYxNDUxRUJGRjEUMBIGCisGAQQBgqJ8AgETBDExOEMxFDASBgorBgEEAYKifAICEwQyMDIyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzFklDsljVKzMwNtBMBHLsx+psYLFYPMiGKKOTq2ur0S1SpcPQTmg0kUnu9X6RfJSnW7qBUJQDsPYXTwRifkv+qNgMF4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFFLhCG3CvDaY1Mu1QtyX2W783wfvMB8GA1UdIwQYMBaAFFm1h6KGoZDqlB20oJiuFdaAAxF4MAoGCCqGSM49BAMCA0gAMEUCIHdFM1UodAqZ73jmDrt786QEn3+jZ0lA7KZy7RzpBJiDAiEA7PRZ0D3NJfq7kKchqww8fDkWGIPwSZ6t5ADlwyuWC5g="
	cert = "MIIBQjCB6qADAgECAgMB4kAwCgYIKoEcz1UBg3UwITELMAkGA1UEBhMCQ04xEjAQBgNVBAMTCVRlc3QgUm9vdDAmFxEyNDAzMDQyMzM3MjMrMDgwMBcRMjYwMzA0MjMzNzIzKzA4MDAwHDELMAkGA1UEBhMCQ04xDTALBgNVBAMTBGFkc2YwUzANBgkqgRzPVQGCLQEFAANCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoxQwEjAQBgNVHRMECXRlc3QgY2VydDAKBggqgRzPVQGDdQNHADBEAiBccVBSujA4p1Y7gzBnBfGPKwjUFSTZ8FeoJHwyjnetfAIgXHFQUrowOKdWO4MwZwXxjysI1BUk2fBXqCR8Mo53rXw="
	decodeBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		fmt.Println(err)
		return
	}
	//原生解析证书工具
	certificates, err := x509.ParseCertificates(decodeBytes)
	//var certObj x509.Certificate
	//certificates, err := asn1.Unmarshal(decodeBytes, &certObj)
	fmt.Println(certificates)
	fmt.Println(err)

}

func Test_create_cert(t *testing.T) {
	//sm2
	//alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}}
	SubjectName := pkix.Name{Country: []string{"CN"}, CommonName: "adsf"}.ToRDNSequence()
	IssuerName := pkix.Name{Country: []string{"CN"}, CommonName: "Test Root"}.ToRDNSequence()
	notBefore := time.Now()
	validity := pkcs.Validity{notBefore, notBefore.AddDate(2, 0, 0)}
	pub := asn1.BitString{Bytes: make([]byte, 65)}
	info := pkcs.SubjectPublicKeyInfo{pkix.AlgorithmIdentifier{asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}, asn1.NullRawValue}, pub}
	//设置版本
	realVersion, _ := asn1.Marshal(2)
	version := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		Bytes:      realVersion,
		IsCompound: true,
	}
	//todo 这个算法标识必须和下面一致
	signAlg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}}
	id := asn1.ObjectIdentifier{2, 5, 29, 19}
	extension := pkix.Extension{Id: id, Value: []byte("test cert")}
	extensions := []pkix.Extension{extension}
	tbs := pkcs.TBSCertificate{Version: version, SerialNumber: big.NewInt(123456), Signature: signAlg, Issuer: IssuerName, Validity: validity, Subject: SubjectName, SubjectPublicKeyInfo: info, Extensions: extensions}

	//SM2Signature转为sequence
	randomData := make([]byte, 256/8)
	rand2.Read(randomData)
	bigInt := new(big.Int).SetBytes(randomData)
	signature := pkcs.SM2Signature{R: bigInt, S: bigInt}
	signatureData, _ := asn1.Marshal(signature)
	//todo 这个算法标识必须和上面一致
	certificate := pkcs.Certificate{tbs, signAlg, asn1.BitString{Bytes: signatureData}}
	fmt.Println(certificate)
	certBytes, err := asn1.Marshal(certificate)
	fmt.Println(err)
	fmt.Println(base64.StdEncoding.EncodeToString(certBytes))
}
