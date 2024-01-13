package x500

import "encoding/asn1"

type ASN1TaggedObject struct {
	tagNo    int
	explicit bool
	obj      ASN1Object
}

func build(tag int, obj ASN1Object) *ASN1TaggedObject {
	return &ASN1TaggedObject{tagNo: tag, explicit: false, obj: obj}
}

func (this *ASN1TaggedObject) Wrapper(data []byte) ASN1Object {
	var result ASN1TaggedObject
	asn1.Unmarshal(data, &result)
	return &result

}

func (this *ASN1TaggedObject) UnWrapper(object ASN1Object) []byte {
	result, _ := asn1.Marshal(object)
	return result
}
