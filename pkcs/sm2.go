package pkcs

import "math/big"

// SM2签名结构
type SM2Signature struct {
	R *big.Int
	S *big.Int
}

// SM2密文结构 C1 C3 C2
type SM2Cipher struct {
	X          *big.Int "x分量"
	Y          *big.Int "y分量"
	Hash       []byte   "size 32"
	CipherText []byte   "密文"
}
