package key

import (
	"crypto/ecdsa"
	"errors"
	"encoding/hex"
	"math/big"
	
	"github.com/btcsuite/btcd/btcec/v2"
)

const compressedPublicKeySize = 33
const unCompressedPublicKeySize = 65

type PublicKey struct {
	x, y *big.Int
	compressed []byte
	unCompressed []byte
}

func ValidatePublicKeyCoord(x, y *big.Int) error {
	if x == nil || y == nil {
        return errors.New("Invalid coordinates: x or y is nil")
    }

    if x.Sign() == 0 && y.Sign() == 0 {
        return errors.New("Invalid point: point at infinity")
    }

	return nil
}

func ValidatePublicKeyByte(publicKeyByte []byte) error {
	if len(publicKeyByte) != 33 && len(publicKeyByte) != 65 {
		return errors.New("Invalid private key length: must be 33 or 65 bytes")
	}

	publicKeyhex := hex.EncodeToString(publicKeyByte)
	if publicKeyhex[:2] != "02" && publicKeyhex[:2] != "03" && publicKeyhex[:2] != "04" {
        return errors.New("Invalid public key prefix: must be 0x02, 0x03 or 0x04")
    }

	return nil
}

func NewPublicKey(x, y *big.Int) (*PublicKey, error) {
	err := ValidatePublicKeyCoord(x, y)
	if err != nil {
		return nil, err
	}

	prefix := byte(0x02)
	if y.Bit(0) == 1 {
		prefix = 0x03
	}
	compressedPublicKey := make([]byte, compressedPublicKeySize)
	compressedPublicKey[0] = prefix
	copy(compressedPublicKey[1:], x.FillBytes(make([]byte, 32)))

	prefix = byte(0x04)
	unCompressedPublicKey := make([]byte, unCompressedPublicKeySize)
	unCompressedPublicKey[0] = prefix
	copy(unCompressedPublicKey[1:], x.FillBytes(make([]byte, 32)))
	copy(unCompressedPublicKey[33:], y.FillBytes(make([]byte, 32)))

	return &PublicKey{x, y, compressedPublicKey, unCompressedPublicKey}, nil
}

func PublicKeyFromByte(publicKeyByte []byte) (*PublicKey, error) {
	err := ValidatePublicKeyByte(publicKeyByte)
	if err != nil {
		return nil, err
	}

	parsedPublicKey, err := btcec.ParsePubKey(publicKeyByte)
	x := parsedPublicKey.ToECDSA().X 
	y := parsedPublicKey.ToECDSA().Y

	prefix := byte(0x02)
	if y.Bit(0) == 1 {
		prefix = 0x03
	}
	compressedPublicKey := make([]byte, compressedPublicKeySize)
	compressedPublicKey[0] = prefix
	copy(compressedPublicKey[1:], x.FillBytes(make([]byte, 32)))

	prefix = byte(0x04)
	unCompressedPublicKey := make([]byte, unCompressedPublicKeySize)
	unCompressedPublicKey[0] = prefix
	copy(unCompressedPublicKey[1:], x.FillBytes(make([]byte, 32)))
	copy(unCompressedPublicKey[33:], y.FillBytes(make([]byte, 32)))
	
	return &PublicKey{x: x, 
					  y: y, 
					  compressed: compressedPublicKey,
					  unCompressed: unCompressedPublicKey,
					}, nil
}

func (k *PublicKey) Serialize() []byte {
	return k.compressed
}

func (k *PublicKey) SerializeUnCompressed() []byte {
	return k.unCompressed
}

func (k *PublicKey) Hex() string {
	return hex.EncodeToString(k.compressed)
}

func (k *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		btcec.S256(),
		k.x,
		k.y,
	}
}