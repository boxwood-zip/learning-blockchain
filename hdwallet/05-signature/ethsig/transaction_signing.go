package ethsig

import (
	"fmt"
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/boxwood-zip/learning-blockchain/hdwallet/04-transaction/ethtx"
)

type Signer = EIP155Signer

// SignTx returns legacy transaction signed with EIP155 standard.
func SignTx(tx *ethtx.LegacyTransaction, signer Signer, privateKey *ecdsa.PrivateKey) (string, error) {
	h := signer.Hash(tx)
	sig, err := crypto.Sign(h[:], privateKey)
	if err != nil {
		return "", fmt.Errorf("signature failed: %v", err)
	}

	return ApplySignature(tx, sig, signer), nil
}

// ApplySignature encodes legacy transaction with signature data.
func ApplySignature(tx *ethtx.LegacyTransaction, sig []byte, signer Signer) string {
	r, s, v := signer.SignatureValues(sig)

	signedTxData := []interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.GasLimit(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		v, r, s,
	}

	// RLP encoding before convert to hex 
	var encoded bytes.Buffer
	err := rlp.Encode(&encoded, signedTxData)
	if err != nil {
		fmt.Println("RLP encoding failed:", err)
		return ""
	}

	return "0x" + hex.EncodeToString(encoded.Bytes())
}