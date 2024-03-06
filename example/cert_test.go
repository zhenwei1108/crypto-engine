package example

import (
	"crypto-engine/src/sm2"
	engineX509 "crypto-engine/src/x509"
	"crypto/rand"
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
	//cert = "MIICETCCAbWgAwIBAgINKl81oFaaablKOp0YTjAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDgxMzIwMTkzNFoXDTIwMTAyNDE1NTk1OVowHjELMAkGA1UEBgwCQ04xDzANBgNVBAMMBuWGr+i9rDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAIF97Sqq0Rv616L2PjFP3xt16QGJLmi+W8Ht+NLHiXntgUey0Nz+ZVnSUKUMzkKuGTikY3h2v7la20b6lpKo8WjgZIwgY8wCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBSxiaS6z4Uguz3MepS2zblkuAF/LTAfBgNVHSMEGDAWgBTMZyRCGsP4rSes0vLlhIEf6cUvrjBABgNVHSAEOTA3MDUGCSqBHIbvMgICAjAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAMBggqgRzPVQGDdQUAA0gAMEUCIG6n6PG0BOK1EdFcvetQlC+9QhpsTuTui2wkeqWiPKYWAiEAvqR8Z+tSiYR5DIs7SyHJPWZ+sa8brtQL/1jURvHGxU8="
	decodeBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		fmt.Println(err)
		return
	}
	//原生解析证书工具
	//certificates, err := x509.ParseCertificates(decodeBytes)
	var certObj engineX509.Certificate
	_, err = asn1.Unmarshal(decodeBytes, &certObj)
	fmt.Println(certObj.SignatureAlgorithm)
	fmt.Println(err)

}

func Test_create_cert(t *testing.T) {
	//sm2
	//alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}}
	SubjectName := pkix.Name{Country: []string{"CN"}, CommonName: "adsf"}.ToRDNSequence()
	IssuerName := pkix.Name{Country: []string{"CN"}, CommonName: "Test Root"}.ToRDNSequence()
	notBefore := time.Now()
	validity := engineX509.Validity{notBefore, notBefore.AddDate(2, 0, 0)}
	//pkcs 8 的公钥
	pubString := "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAET2aKBJNS1+09pI28CkeEGvBLQXER9+BFMEEvr8BJ4HgrGrM/ha9wU1V3SpIGJv/3WeslARuwCCEZOooRDNfOLg=="
	pubBytes, _ := base64.StdEncoding.DecodeString(pubString)
	//pub := asn1.BitString{Bytes: pubBytes}
	info := engineX509.SubjectPublicKeyInfo{}
	_, err2 := asn1.Unmarshal(pubBytes, &info)
	if err2 != nil {
		fmt.Println(err2)
	}
	//info := pkcs.SubjectPublicKeyInfo{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}}, pub}
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
	tbs := engineX509.TBSCertificate{Version: version,
		SerialNumber:         big.NewInt(123456),
		Signature:            signAlg,
		Issuer:               IssuerName,
		Validity:             validity,
		Subject:              SubjectName,
		SubjectPublicKeyInfo: info,
		Extensions:           extensions}

	//SM2Signature转为sequence
	randomData := make([]byte, 256/8)
	rand.Read(randomData)
	bigInt := new(big.Int).SetBytes(randomData)
	signature := sm2.SM2Signature{R: bigInt, S: bigInt}
	signatureData, _ := asn1.Marshal(signature)
	//todo 这个算法标识必须和上面一致
	certificate := engineX509.Certificate{tbs, signAlg, asn1.BitString{Bytes: signatureData}}
	fmt.Println(certificate)
	certBytes, err := asn1.Marshal(certificate)
	fmt.Println(err)
	fmt.Println(base64.StdEncoding.EncodeToString(certBytes))
	fmt.Println("---------------")
	certificates, err := x509.ParseCertificates(certBytes)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(certificates)

}
