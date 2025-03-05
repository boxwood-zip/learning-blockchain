package key

import (
	"errors"
	"strconv"
	"strings"
)

type ExtendedKey struct {
	privKey *PrivateKey
	pubKey *PublicKey
	chainCode []byte
	depth uint8
	isPrivate bool
}

func NewExtendedKey(pirvKey *PrivateKey, pubKey *PublicKey, chainCode []byte, depth uint8, isPrivate bool) *ExtendedKey {
	return &ExtendedKey{
		privKey: pirvKey,
		pubKey: pubKey,
		chainCode: chainCode,
		depth: depth,
		isPrivate: isPrivate,
	}
}

func (e *ExtendedKey) DerivePath(path string) (*ExtendedKey, error) {
	paths := strings.Split(path, "/")

	if paths[0] != "m" {
		return &ExtendedKey{}, errors.New("Follow bip-44 standards derivation path.")
	}

	key := e
	for _, p := range paths[1:] {
		pUint64, err := strconv.ParseInt(string(p[0]), 10, 64)
		if err != nil {
			return &ExtendedKey{}, err 
		}

		var index uint32
		if p[len(p)-1] == byte('\'') {
			index = uint32(pUint64) + HardenedOffset
		} else {
			index = uint32(pUint64)
		}

		key, err = key.Derive(index)
		if err != nil {
			return &ExtendedKey{}, err
		}
	}

	return key, nil
}

func (e *ExtendedKey) Derive(index uint32) (*ExtendedKey, error) {
	if e.isPrivate {
		childPrivateKey, childChainCode, err := DerivePrivateKey(e.privKey, e.chainCode, index)
		if err != nil {
			return nil, err
		}

		return &ExtendedKey{
			privKey: childPrivateKey,
			chainCode: childChainCode,
			depth: e.depth+1,
			isPrivate: true,
		}, nil
	} else {
		if index >= HardenedOffset {
			return nil, errors.New("Public hardened key cannot be derived from the public key.")
		}
		childPublicKey, childChainCode, err := DerivePublicKey(e.pubKey, e.chainCode, index)
		if err != nil {
			return nil, err
		}

		return &ExtendedKey{
			pubKey: childPublicKey,
			chainCode: childChainCode,
			depth: e.depth+1,
			isPrivate: false,
		}, nil
	}
}