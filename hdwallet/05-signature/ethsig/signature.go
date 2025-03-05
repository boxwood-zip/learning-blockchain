package ethsig

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/boxwood-zip/learning-blockchain/hdwallet/04-transaction/ethtx"
)

type EIP155Signer struct {
	chainID, chainIDMul *big.Int
}

func NewEIP155Signer(chainId *big.Int) EIP155Signer {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return EIP155Signer{
		chainID:    chainId,
		chainIDMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

// rlpHash performs rlp encoding and Keccak256 hashing.
func rlpHash(data interface{}) common.Hash {
	bytes, _ := rlp.EncodeToBytes(data)
	return crypto.Keccak256Hash(bytes)
}

// Hash Keccak256 hashes legacy transaction after rlp encoding.
func (es *EIP155Signer) Hash(tx *ethtx.LegacyTransaction) common.Hash {
	return rlpHash([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.GasLimit(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		tx.ChainID(), uint(0), uint(0),
	})
}

// SignatureValues applies the EIP-155 to signature data
func (es *EIP155Signer) SignatureValues(sig []byte) (r,s,v *big.Int) {
	// separate signature values (r,s,v)
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = big.NewInt(int64(sig[64] + 27)) // Ethereum V 값 (27 or 28)

	// apply EIP-155
	if es.chainID.Sign() != 0 {
		v = big.NewInt(int64(sig[64] + 35))
		v.Add(v, es.chainIDMul)
	}

	return r, s, v
}