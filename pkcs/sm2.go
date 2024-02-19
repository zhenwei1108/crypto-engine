package pkcs

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

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

type SM2PublicKey struct {
	elliptic.Curve
	X *big.Int
	Y *big.Int
}

type SM2KeyPair struct {
	PublicKey  SM2PublicKey
	PrivateKey asn1.BitString
}

/**密钥保护结构*/
type SM2EnvelopedKey struct {
	SymAlgID               pkix.AlgorithmIdentifier
	SymEncryptData         SM2Cipher
	Sm2PublicKey           SM2PublicKey
	Sm2EncryptedPrivateKey asn1.BitString
}
