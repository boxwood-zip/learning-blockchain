package address

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"github.com/boxwood-zip/learning-blockchain/hdwallet/02-key_derivation/key"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ToP2PKHAddress converts uncompressed public key to p2pkh address
func ToP2PKHAddress(publicKey *key.PublicKey, isTestnet bool) string {
	sha256Hash := sha256.Sum256(publicKey.SerializeUnCompressed())

	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Hash[:])
	pubKeyHash := ripemd160Hasher.Sum(nil)

	var prefix byte
	if isTestnet {
		prefix = 0x6F
	} else {
		prefix = 0x00
	}
	prefixPayload := append([]byte{prefix}, pubKeyHash...)

	firstSHA := sha256.Sum256(prefixPayload)
	secondSHA := sha256.Sum256(firstSHA[:])
	checksum := secondSHA[:4]

	fullPayload := append(prefixPayload, checksum...)

	return base58Encode(fullPayload)
}

// base58Encode encodes string
func base58Encode(input []byte) string {
	var result []byte
	num := new(big.Int).SetBytes(input)

	base := big.NewInt(58)
	zero := big.NewInt(0)

	for num.Cmp(zero) > 0 {
		mod := new(big.Int)
		num.DivMod(num, base, mod)
		result = append([]byte{base58Alphabet[mod.Int64()]}, result...)
	}

	return string(result)
}

// ToEIP55Address converts uncompressed public key to eip55 address
func ToEIP55Address(publicKey *key.PublicKey) (string, error) {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(publicKey.SerializeUnCompressed()[1:])
	addressHash := hasher.Sum(nil)

	address := "0x" + hex.EncodeToString(addressHash[len(addressHash[:])-20:])

	return eip55Checksum(address)
}

// eip55Checksum changes the upper and low case of the address according to the Keccak256 hash value
func eip55Checksum(address string) (string, error) {
	if len(address) != 42 {
		return "", errors.New("Invalid address length: must be 42 characters")
	}

	if address[:2] != "0x" {
		return "", errors.New("Invalid address: must be start with 0x")
	}

	address = strings.ToLower(address[2:])

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(address))
	addressHash := hasher.Sum(nil)

	eip55Address := "0x"
	for i, c := range address {
		hashByte := addressHash[i/2]
		hashNibble := hashByte
		if i%2 == 0 {
			hashNibble = hashByte>>4
		} else {
			hashNibble = hashByte & 0x0f
		}

		if c >= '0' && c <= '9' {
			eip55Address += string(c)
		} else {
			if hashNibble >= 8 {
				eip55Address += strings.ToUpper(string(c))
			} else {
				eip55Address += string(c)
			}
		}
	}

	return eip55Address, nil
}