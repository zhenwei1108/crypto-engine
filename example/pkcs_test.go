package example

import (
	"crypto-engine/src/pkcs7"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

//func Test_pkcs(t *testing.T) {
//	fmt.Println("start test")
//	msg := []byte{1, 2, 3}
//	oct := x509.OctetString{msg}
//	dataResult := base.Data{oct}
//
//	tag := x509.ASN1TaggedObject{0, false, dataResult}
//	objId := asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1}
//	contentType := base.ContentType{tag}
//	contentInfo := base.ContentInfo{objId, contentType}
//
//	//var result []byte
//	marshal, err := asn1.Marshal(contentInfo)
//	//rest, err := asn1.Unmarshal(result, &contentInfo)
//	if err != nil {
//		fmt.Println("err", err)
//		fmt.Println(hex.Dump(marshal))
//	}
//	fmt.Println(hex.Dump(marshal))
//	fmt.Println(hex.EncodeToString(marshal))
//	fmt.Println("end ")
//
//}

func Test_build(test *testing.T) {
	result, err := pkcs7.BuildPkcs7Data([]byte("dadsf"), true)
	if err != nil {
		fmt.Println(err)
	}
	//todo 指针变对象
	fmt.Println(reflect.TypeOf(*result))
	marshal, err := asn1.Marshal(*result)
	fmt.Println(err)
	fmt.Println(hex.EncodeToString(marshal))

}
