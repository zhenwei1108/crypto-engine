package pkcs

import "math/big"

type SM2Signature struct {
	r big.Int
	s big.Int
}

// C1 C3 C2
type SM2Cipher struct {
	x          big.Int "x分量"
	y          big.Int "y分量"
	hash       []byte  "size 32"
	cipherText []byte  "密文"
}
