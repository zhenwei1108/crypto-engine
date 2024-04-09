package x509

var (
	ID_CE                   = []int{2, 5, 29}
	KEY_USAGE               = append(ID_CE, 15)
	EXT_KEY_USAGE           = append(ID_CE, 37)
	CERTIFICATE_POLICIES    = append(ID_CE, 32)                //证书策略
	SUBJECT_KEY_ID          = append(ID_CE, 14)                //使用者密钥标识符
	AUTHOR_KEY_ID           = append(ID_CE, 35)                //颁发者密钥标识符
	POLICY_MAPPING          = append(ID_CE, 33)                //映射策略
	SUBJECT_ALT_NAME        = append(ID_CE, 17)                //主体替换名称
	BASIC_CONSTRAINTS       = append(ID_CE, 19)                //基本限制
	CRL_DISTRIBUTION_POINTS = append(ID_CE, 31)                //CRL发布点
	IDENTIFY_CODE           = []int{1, 2, 156, 10260, 4, 1, 1} //个人身份标识码
	INSURANCE_NUMBER        = []int{1, 2, 156, 10260, 4, 1, 2} //个人社会保险号

)
