package mnemonic

import (
	"encoding/hex"
	"testing"
	"log"
)

const length = 256

func TestMnemonic(t *testing.T) {
	mnemonic, err := GenerateMnemonic(length)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("mnemonic: ", mnemonic)

	masterSeed := GenerateMasterSeed([]byte(mnemonic), []byte("mnemonic1234"))
	log.Println("masterSeed: 0x" + hex.EncodeToString(masterSeed))
}