package x500

type ASN1Object interface {
	//包装
	wrapper([]byte) ASN1Object
	//解析
	unWrapper(object ASN1Object) []byte
}
