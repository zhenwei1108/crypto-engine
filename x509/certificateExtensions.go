package x509

import (
	"encoding/asn1"
	"strings"
)

var (
	ID_CE                   = []int{2, 5, 29}
	SUBJECT_KEY_ID          = asn1.ObjectIdentifier(append(ID_CE, 14)) //使用者密钥标识符
	KEY_USAGE               = asn1.ObjectIdentifier(append(ID_CE, 15))
	SUBJECT_ALT_NAME        = asn1.ObjectIdentifier(append(ID_CE, 17)) //主体替换名称
	BASIC_CONSTRAINTS       = asn1.ObjectIdentifier(append(ID_CE, 19)) //基本限制
	CRL_DISTRIBUTION_POINTS = asn1.ObjectIdentifier(append(ID_CE, 31)) //CRL发布点
	CERTIFICATE_POLICIES    = asn1.ObjectIdentifier(append(ID_CE, 32)) //证书策略
	POLICY_MAPPING          = asn1.ObjectIdentifier(append(ID_CE, 33)) //映射策略
	AUTHOR_KEY_ID           = asn1.ObjectIdentifier(append(ID_CE, 35)) //颁发者/授权者密钥标识符
	EXT_KEY_USAGE           = asn1.ObjectIdentifier(append(ID_CE, 37))

	IDENTIFY_CODE    = asn1.ObjectIdentifier([]int{1, 2, 156, 10260, 4, 1, 1}) //个人身份标识码
	INSURANCE_NUMBER = asn1.ObjectIdentifier([]int{1, 2, 156, 10260, 4, 1, 2}) //个人社会保险号

)

func MatchKeyUsage(data asn1.BitString) string {
	var usage string
	//密钥用途占 9 位
	for i := 0; i < 9; i++ {
		//fmt.Println(data.At(i)) //1 1 0 0 0 0 0
		if data.At(i) != 0 {
			usage += (catchUsage(uint(i)+1) + " ")
		}
	}
	return strings.ReplaceAll(strings.TrimSuffix(usage, " "), " ", "|")
}

/*
KeyUsageDigitalSignature KeyUsage = 1 << iota
*/
func catchUsage(usage uint) string {
	switch usage {
	case 1: //KeyUsageDigitalSignature
		return "数据签名"
	case 2: //KeyUsageContentCommitment
		return "不可抵赖"
	case 3: //KeyUsageKeyEncipherment
		return "密钥加密"
	case 4: //KeyUsageDataEncipherment
		return "数据加密"
	case 5: //KeyUsageKeyAgreement
		return "密钥协商"
	case 6: //KeyUsageCertSign
		return "证书签发"
	case 7: //KeyUsageCRLSign
		return "CRL签发"
	case 8: // KeyUsageEncipherOnly
		return "只加密"
	case 9: //KeyUsageDecipherOnly
		return "只解密"
	}
	return ""
}
