module github.com/boxwood-zip/learning-blockchain

go 1.23.6

replace github.com/boxwood-zip/learning-blockchain/hdwallet/01-mnemonic/mnemonic => ./hdwallet/01-mnemonic/mnemonic

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	golang.org/x/crypto v0.35.0 // indirect
)
