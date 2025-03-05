package ethsig

import (
	"context"
	"testing"
	"time"
	"log"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/boxwood-zip/learning-blockchain/hdwallet/04-transaction/ethtx"
)

var (
	toAddressHex = "0xD8Ea779b8FFC1096CA422D40588C4c0641709890"
	privateKeyHex = "fd30d9f520e834ea0abebe8933c741d63a6e11def16aa3495110f0449ff26156"
	rpcURL = "wss://ethereum-sepolia-rpc.publicnode.com"
	blockConfirmations = uint64(1)
)

func TestEIP155Signer(t *testing.T) {
	// Connect to Ethereum client
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	// Private key (in production, should be retrieved from environment variables or secure storage)
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		log.Fatalf("Convert private key failed: %v", err)
	}
	
	// Recipient address
	toAddress := toAddressHex
	
	// Amount to send (0.0001 ETH)
	value := new(big.Int).Mul(big.NewInt(100000000000000), big.NewInt(1)) // 0.0001 ETH
	
	// Gas limit
	gasLimit := uint64(21000) // Default gas limit for ETH transfers
	
	// Create transaction
	tx, err := ethtx.NewLegacyTransaction(
		client,
		privateKeyHex,
		toAddress,
		value,
		nil, // No data
		gasLimit,
	)
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	// transaction signature
	signedTxHex, err:= SignTx(tx, NewEIP155Signer(tx.ChainID()), privateKey)
	if err != nil {
		log.Fatalf("signature failed: %v", err)
	}
	log.Println("signed transaction: ", signedTxHex)

	// send transaction to ethereum network
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	rpcClient, err := rpc.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Contect RPC failed: %v", err)
	}

	txHash, err := tx.SendRaw(rpcClient, ctx, signedTxHex)
	if err != nil {
		log.Fatalf("transaction send failed: %v", err)
	}

	fmt.Println("transaction has been sent.")
	fmt.Println("transaction hash: ", txHash)

	// Confirm transaction (wait for 3 block confirmations)
	receipt, err := tx.Confirm(ctx, blockConfirmations)
	if err != nil {
		log.Fatalf("Failed to confirm transaction: %v", err)
	}
	
	// Output receipt information
	fmt.Printf("Transaction successfully confirmed.\n")
	fmt.Printf("Gas used: %d\n", receipt.GasUsed)
	fmt.Printf("Status: %d\n", receipt.Status)
}