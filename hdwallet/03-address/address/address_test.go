package address

import (
	"encoding/hex"
	"testing"
	"log"

	"github.com/boxwood-zip/learning-blockchain/hdwallet/02-key_derivation/key"
)

var (
	bitcoinPublicKeyHex = "0408f439970bbe897385d9b6dbfac9be9590e8d5310af429833eda8858f61f141c5fae7a077e89cdb808a7bdd97d0cf70fd60310ddaf5d0c719de88dbb037540c0"
	ethereumPublicKeyHex = "0425d199a0d145e028a5bf0fbd76a20b72564b17a51c6f429aca4b1d1276f90bc4eb9304ec4ed4ae85364d858cfee634b02b476186077274a8fb33fc9042af7221"
)

func TestAddress(t *testing.T) {
	bitcoinPublicKeyBytes, _ := hex.DecodeString(bitcoinPublicKeyHex)
	bitcoinPublickey, _ := key.PublicKeyFromByte(bitcoinPublicKeyBytes)
	btcAddress := ToP2PKHAddress(bitcoinPublickey, true)
	log.Println(btcAddress)

	ethereumPublicKeyBytes, _ := hex.DecodeString(ethereumPublicKeyHex)
	ethereumPublicKey, _ := key.PublicKeyFromByte(ethereumPublicKeyBytes)
	ethAddress, _ := ToEIP55Address(ethereumPublicKey)
	log.Println(ethAddress)
}
