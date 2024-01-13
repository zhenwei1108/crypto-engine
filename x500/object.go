package x500

type ASN1Object interface {
	//包装
	Wrapper([]byte) ASN1Object
	//解析
	UnWrapper(object ASN1Object) []byte
}
