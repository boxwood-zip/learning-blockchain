package key

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
)

const HardenedOffset = 0x80000000

var (
	n, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	masterKeyString = []byte("Bitcoin seed")
)

func NewMasterFromSeed(seed []byte) (*ExtendedKey, error) {
	h := hmac.New(sha512.New, masterKeyString)
	h.Write(seed)
	h512 := h.Sum(nil)
	masterPrivateKeyByte := h512[:len(h512)/2]
	masterChainCodeByte := h512[len(h512)/2:]

	masterPrivateKey, err := PrivateKeyFromByte(masterPrivateKeyByte)
	if err != nil {
		return nil, err
	}

	return &ExtendedKey{
		privKey: masterPrivateKey,
		chainCode: masterChainCodeByte,
		depth: 0,
		isPrivate: true,
	}, nil
}

func DerivePublicKey(parentPublicKey *PublicKey, parentChainCode []byte, index uint32) (*PublicKey, []byte, error) {
	if index >= HardenedOffset {
		return nil, nil, errors.New("Invalid index range: index exceeds maximum value 0x" + strconv.FormatInt(HardenedOffset-1, 16))
	}

	data := GenerateNormalKeyData(parentPublicKey.Serialize(), index)
	h := hmac.New(sha512.New, parentChainCode)
	h.Write(data)
	I := h.Sum(nil)

	IL := I[:32]
	IR := I[32:]
	ILInt := new(big.Int).SetBytes(IL)
	if ILInt.Cmp(n) >= 0 {
		return nil, nil, errors.New("Invalid index value: should proceed with the next value for index")
	}

	curve := btcec.S256()
	x, y := curve.ScalarBaseMult(ILInt.FillBytes(make([]byte, privateKeySize)))
	childKeyX, childKeyY := curve.Add(parentPublicKey.x, parentPublicKey.y, x, y)
	err := ValidatePublicKeyCoord(childKeyX, childKeyY)
	if err != nil {
		return nil, nil, errors.New("Invalid index value: should proceed with the next value for index")
	}

	var childPublicKey *PublicKey
	childPublicKey, err = NewPublicKey(childKeyX, childKeyY)
	if err != nil {
		return nil, nil, err
	}

	return childPublicKey, IR, nil
}

func DerivePrivateKey(parentPrivateKey *PrivateKey, parentChainCode []byte, index uint32) (*PrivateKey, []byte, error) {
	var data []byte
	if index >= HardenedOffset {
		data = GenerateHardenedKeyData(parentPrivateKey.Serialize(), index)
	} else {
		data = GenerateNormalKeyData(parentPrivateKey.PublicKey().Serialize(), index)
	}
	h := hmac.New(sha512.New, parentChainCode)
	h.Write(data)
	I := h.Sum(nil)

	IL := I[:32]
	IR := I[32:]
	ILInt := new(big.Int).SetBytes(IL)
	if ILInt.Cmp(n) >= 0 {
		return nil, nil, errors.New("Invalid index value: should proceed with the next value for index")
	}

	childKeyInt := new(big.Int)
	childKeyInt.Add(parentPrivateKey.D, ILInt)
	childKeyInt.Mod(childKeyInt, n)
	if childKeyInt.Cmp(new(big.Int).SetInt64(0)) == 0 {
		return nil, nil, errors.New("Invalid index value: should proceed with the next value for index")
	}

	childPrivateKey, err := PrivateKeyFromByte(childKeyInt.FillBytes(make([]byte, privateKeySize)))
	if err != nil {
		return nil, nil, err
	}

	return childPrivateKey, IR, nil
}

func GenerateHardenedKeyData(privateKeyByte []byte, index uint32) []byte {
	data := make([]byte, 37)
	data[0] = 0x00
	copy(data[1:], privateKeyByte)
	binary.BigEndian.PutUint32(data[33:], index)
	return data
}

func GenerateNormalKeyData(publicKeyByte []byte, index uint32) []byte {
	data := make([]byte, 37)
	copy(data, publicKeyByte)
	binary.BigEndian.PutUint32(data[33:], index)
	return data
}