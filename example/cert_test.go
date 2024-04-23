package example

import (
	"crypto-engine/src/sm2"
	engineX509 "crypto-engine/src/x509"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func Test_code_cert(t *testing.T) {
	var cert = "MIIEfjCCA2agAwIBAgIQefIDuSADkosPySFwsKcsjDANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJDTjEmMCQGA1UECgwdQkVJSklORyBDRVJUSUZJQ0FURSBBVVRIT1JJVFkxGTAXBgNVBAMMEEJKQ0EgRG9jU2lnbiBDQTMwHhcNMjAxMjA3MDc1MDAwWhcNMjExMjA3MDc1MDAwWjBIMQswCQYDVQQGEwJDTjElMCMGA1UECwwcYmI1Tndlbk5kYVg2ZkhNd1VKUlkvQTFOVDcwPTESMBAGA1UEAwwJ5p2O5Li96ZyeMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzeiCgLXKDzzBsLLHedJKG11m6SotdlynexHe8cI1TmWa3ODerwBHukr5ZkJft3seIQqFHi6xVlNgfOHO5WNgCKpvg/HxRoQshwLDYgeH5KcpH67dv1dl6urqwvwzSE5gmJo1+OGqAl9yeG9X76zkueZUd4v3RrVOoofbTlSBkWoigXH/0mpu/vgxhDRzmksNQvZ+Ay2jisdshpZovH6a+ABYMYMYo4U1o6BfvHBKEPo20TDJ/t0KlVRoHkgiMvtO8NOI5d0cxea5RaOCDT10CGHheqieMibUQnCkB6Yi01aoDQxtG8TshO7uGWoMzqPPs+u44Ym1s2LH51fvTS6bHQIDAQABo4IBWjCCAVYwcQYIKwYBBQUHAQEEZTBjMEAGCCsGAQUFBzAChjRodHRwOi8vcmVwby5iamNhLmNuL2dsb2JhbC9jZXJ0L0JKQ0FfRG9jU2lnbl9DQTMuY3J0MB8GCCsGAQUFBzABhhNodHRwOi8vb2NzcC5iamNhLmNuMB0GA1UdDgQWBBQh7RHFVos8ievEiiAvASMjEmqw+zAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFCA6epfxEmaXv3PW5YXPR9M0GLwyMD0GA1UdIAQ2MDQwMgYJKoEchu8yAgIWMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vd3d3LmJqY2EuY24vQ1BTMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9yZXBvLmJqY2EuY24vZ2xvYmFsL2NybC9CSkNBX0RvY1NpZ25fQ0EzLmNybDAOBgNVHQ8BAf8EBAMCBsAwDQYJKoZIhvcNAQELBQADggEBAF5apKpbT9EG+gJP82LKKwbW9/jUJ/9tZEzPKfX4Uqs7YB3DCnM78qLBKvHByP9bUv2L7Yd6ncv9FORJqw6KEJiNz6/wXcNsNN/MYj8tZNonMyTW+tGkoRR0AqPWHZ1Cq+M0LFYuL8uwkMXDPZiHrrwtwNrr5cSsrYiamDyoZAe6MRzBiU9WgpzGWbMPu+IRoYye04Cq/yEVBsHLnUR24wehUVgPJb68tR7j3M3Yc3gSbTb9ymFFfETxaf2qDUelnr7CqhM/Ddj77dnZ86ZUGi95l7SDeEQW56EL9Og4TnLuL7A0tOPZhADwY5mgiQbLiMziO7szirh8wK8R5njJ9gI="
	//个人证书？
	//cert = "MIICETCCAbWgAwIBAgINKl81oFaaablKOp0YTjAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDgxMzIwMTkzNFoXDTIwMTAyNDE1NTk1OVowHjELMAkGA1UEBgwCQ04xDzANBgNVBAMMBuWGr+i9rDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAIF97Sqq0Rv616L2PjFP3xt16QGJLmi+W8Ht+NLHiXntgUey0Nz+ZVnSUKUMzkKuGTikY3h2v7la20b6lpKo8WjgZIwgY8wCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBSxiaS6z4Uguz3MepS2zblkuAF/LTAfBgNVHSMEGDAWgBTMZyRCGsP4rSes0vLlhIEf6cUvrjBABgNVHSAEOTA3MDUGCSqBHIbvMgICAjAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAMBggqgRzPVQGDdQUAA0gAMEUCIG6n6PG0BOK1EdFcvetQlC+9QhpsTuTui2wkeqWiPKYWAiEAvqR8Z+tSiYR5DIs7SyHJPWZ+sa8brtQL/1jURvHGxU8="
	decodeBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		fmt.Println(err)
		return
	}
	//原生解析证书工具
	//certificates, err := x509.ParseCertificates(decodeBytes)
	var certificates engineX509.Certificate
	_, err = asn1.Unmarshal(decodeBytes, &certificates)
	extensions := certificates.TbsCertificate.Extensions
	for _, extension := range extensions {
		id := extension.Id
		if id.Equal(engineX509.CRL_DISTRIBUTION_POINTS) {
			fmt.Println("crl 扩展", hex.EncodeToString(extension.Value))
			var distributionPoints []engineX509.DistributionPoint
			_, err := asn1.Unmarshal(extension.Value, &distributionPoints)
			if err != nil {
				fmt.Println("异常", err)
			}
			for _, distributionPoint := range distributionPoints {
				marshal, _ := asn1.Marshal(distributionPoint)
				fmt.Println("HEX: ", hex.EncodeToString(marshal))
				name := distributionPoint.DistributionPointName.FullName
				name.Matcher()
				fmt.Println("打印: ", name.URI)
				var name1 engineX509.Name
				_, err := asn1.Unmarshal(name.DirectoryName.Bytes, &name1)
				fmt.Println(err)
				fmt.Println(name1.ToString())
				fmt.Println("打印: ", name.DirectoryName.Bytes)
				fmt.Println("full: " + hex.EncodeToString(name.DirectoryName.FullBytes))
			}

		}

	}

	fmt.Println(certificates)
	fmt.Println(err)

}

func Test_create_cert(t *testing.T) {
	//sm2
	//alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}}
	SubjectName := pkix.Name{Country: []string{"newString"}, CommonName: "adsf汉字"}.ToRDNSequence()
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
		Issuer:               engineX509.Name(SubjectName),
		Validity:             validity,
		Subject:              engineX509.Name(IssuerName),
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
