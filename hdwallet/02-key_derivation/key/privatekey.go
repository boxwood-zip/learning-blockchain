package key

import (
	"errors"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	
	"github.com/btcsuite/btcd/btcec/v2"
)

const privateKeySize = 32

type PrivateKey struct {
	pubKey *PublicKey
	D *big.Int
}

func ValidatePrivateKeyByte(privateKeyByte []byte) error {
	if privateKeyByte == nil {
		return errors.New("Invalid private key value: private key is nil")
	}
	
	if len(privateKeyByte) != privateKeySize {
		return errors.New("Invalid private key length: must be 32 bytes")
	}

	if binary.BigEndian.Uint32(privateKeyByte) == 0 {
		return errors.New("Invalid private key value: must be at least 10")
	}

	return nil
}

func PrivateKeyFromByte(privateKeyByte []byte) (*PrivateKey, error) {
	err := ValidatePrivateKeyByte(privateKeyByte)
	if err != nil {
		return nil, err
	}

	var D *big.Int
	D = new(big.Int).SetBytes(privateKeyByte)
	x, y := btcec.S256().ScalarBaseMult(D.FillBytes(make([]byte, privateKeySize)))
	compressedPublicKey, err := NewPublicKey(x, y)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{compressedPublicKey, D}, nil
}

func (k *PrivateKey) Serialize() []byte {
	return k.D.FillBytes(make([]byte, privateKeySize))
}

func (k *PrivateKey) Hex() string {
	return "0x" + hex.EncodeToString(k.D.FillBytes(make([]byte, privateKeySize)))
}

func (k *PrivateKey) PublicKey() *PublicKey {
	return k.pubKey
}