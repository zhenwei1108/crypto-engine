package x509

type ASN1TaggedObject struct {
	TagNo    int
	Explicit bool
	Obj      interface{}
}
