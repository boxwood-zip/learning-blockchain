package key

import (
	"testing"
	"log"
	
	"github.com/boxwood-zip/learning-blockchain/hdwallet/01-mnemonic/mnemonic"
)

var mnemonicLength = 256

func TestKeyDerivation(t *testing.T) {
	mnemonicString, _ := mnemonic.GenerateMnemonic(mnemonicLength)
	masterSeed := mnemonic.GenerateMasterSeed([]byte(mnemonicString), []byte("mnemonic1234"))
	masterKey, _ := NewMasterFromSeed(masterSeed)
	log.Println("masterKey.privKey: ", masterKey.privKey.Hex())

	addressKey, _ := masterKey.DerivePath("m/44'/0'/0'/0/0")
	log.Println("addressKey.privKey: ", addressKey.privKey.Hex())
}