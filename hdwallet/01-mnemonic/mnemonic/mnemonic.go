package mnemonic

import (
	"errors"
	"strconv"
	"strings"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

type bits []byte

func GenerateMnemonic(length int) (string, error) {
	// combine generated entropy and checksum
	entropy, err := GenerateEntropy(length)
	if err != nil {
		return "", err
	}
	checksum := CalculateChecksum(entropy)
	sequence := append(ByteToBit(entropy), checksum...)

	// split bits into 12 or 24 segments of 11-bits each
	// and retrived a BIP-39 mnemonic word
	chunkSize := 11
	sequenceCount := len(sequence)/chunkSize
	words := make([]string, sequenceCount)
	for i:=0; i<int(sequenceCount); i++ {
		seg := sequence[i*chunkSize:(i+1)*chunkSize]
		num, _ := strconv.ParseInt(string(seg), 2, 64)
		words[i], err = getWord(int(num))
		if err != nil {
			return "", err
		}
	}
	return strings.Join(words, " "), nil
}

func GenerateMasterSeed(mnemonic []byte, salt []byte) []byte {
	pbkdf2Key := pbkdf2.Key(mnemonic, []byte("mnemonic1234"), 2048, 64, sha512.New)

	return pbkdf2Key
}

// GenerateEntropy generate a random number in bytes length
func GenerateEntropy(length int) ([]byte, error) {
	if length != 128 && length != 256 {
		return nil, errors.New("Invalid length: must be either 128 or 256")
	}

	bytes := make([]byte, length/8)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// CalculateChecksum calculate checksum
func CalculateChecksum(data []byte) bits {
	h := sha256.New()
	h.Write(data)
	h256 := ByteToBit(h.Sum(nil))
	cs := len(data)*8/32
	return h256[:cs]
}

// ByteToBit convert byte data to bits type data
func ByteToBit(bytes []byte) bits {
	length := len(bytes)
	bits := make(bits, length*8)
	
	for i := 0; i < length; i++ {
		b := bytes[i]
		for j := 0 ; j < 8; j++ {
			mask := byte(1 << uint8(7-j))
			bit := b & mask
			if bit == 0 {
				bits[i*8+j] = '0'
			} else {
				bits[i*8+j] = '1'
			}
		}
	}
	return bits
}