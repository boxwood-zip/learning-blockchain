package ethtx

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"
	
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	toAddressHex = "0xD8Ea779b8FFC1096CA422D40588C4c0641709890"
	privateKeyHex = "fd30d9f520e834ea0abebe8933c741d63a6e11def16aa3495110f0449ff26156"
	rpcURL = "wss://ethereum-sepolia-rpc.publicnode.com"
	blockConfirmations = uint64(1)
)

func TestETHTransfer(t *testing.T) {
	// Connect to Ethereum client
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	// Private key (in production, should be retrieved from environment variables or secure storage)
	privateKey := privateKeyHex
	
	// Recipient address
	toAddress := toAddressHex
	
	// Amount to send (0.0001 ETH)
	value := new(big.Int).Mul(big.NewInt(100000000000000), big.NewInt(1)) // 0.01 ETH
	
	// Gas limit
	gasLimit := uint64(21000) // Default gas limit for ETH transfers
	
	// Create transaction
	tx, err := NewEIP1559Transaction(
		client,
		privateKey,
		toAddress,
		value,
		nil, // No data
		gasLimit,
	)
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}
	
	// Send transaction
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	
	_, err = tx.Send(ctx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}
	
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