package ethereum

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// LegacyTransaction structure
type LegacyTransaction struct {
	client       *ethclient.Client
	privateKey   *ecdsa.PrivateKey
	to           common.Address
	value        *big.Int
	data         []byte
	nonce        uint64
	gasPrice     *big.Int
	gasLimit     uint64
	chainID      *big.Int
	txHash       common.Hash
}

// Return the transaction attributes
func (tx *LegacyTransaction) To() common.Address {
	return tx.to
}
func (tx *LegacyTransaction) Value() *big.Int {
	return tx.value
}
func (tx *LegacyTransaction) Data() []byte {
	return tx.data
}
func (tx *LegacyTransaction) Nonce() uint64 {
	return tx.nonce
}
func (tx *LegacyTransaction) GasPrice() *big.Int {
	return tx.gasPrice
}
func (tx *LegacyTransaction) GasLimit() uint64 {
	return tx.gasLimit
}
func (tx *LegacyTransaction) ChainID() *big.Int {
	return tx.chainID
}
func (tx *LegacyTransaction) Hash() common.Hash {
	return tx.txHash
}

// NewLegacyTransaction creates a new Legacy transaction 
func NewLegacyTransaction(
	client *ethclient.Client,
	privateKeyHex string,
	toAddress string,
	value *big.Int,
	data []byte,
	gasLimit uint64,
) (*LegacyTransaction, error) {
	// Private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("private key parsing error: %w", err)
	}

	// ToAddress
	to := common.HexToAddress(toAddress)

	// Nonce
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to convert to ECDSA public key")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, fmt.Errorf("error getting nonce: %w", err)
	}

	// Estimate gas price
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error getting gas price: %v", err)
	}

	// Chain ID
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error getting chain id: %v", err)
	}

	return &LegacyTransaction{
		client:     client,
		privateKey: privateKey,
		to:         to,
		value:      value,
		data:       data,
		nonce:      nonce,
		gasPrice:   gasPrice,
		gasLimit:   gasLimit,
		chainID:    chainID,
	}, nil
}

// Send broadcasts the transaction
func (tx *LegacyTransaction) Send(ctx context.Context) (string, error) {
	// Create legacy transaction
	rawTx := types.NewTransaction(
		tx.nonce,
		tx.to,
		tx.value,
		tx.gasLimit,
		tx.gasPrice,
		tx.data,
	)

	// Sign transaction
	signedTx, err := types.SignTx(rawTx, types.NewEIP155Signer(tx.chainID), tx.privateKey)
	if err != nil {
		return "", fmt.Errorf("transaction signing error: %w", err)
	}

	// Send transaction
	err = tx.client.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("transaction sending error: %w", err)
	}

	fmt.Println("transaction has been sent.")
	txAsJson, err := json.MarshalIndent(signedTx, "", "  ")
	fmt.Println(string(txAsJson))
	
	return signedTx.Hash().Hex(), nil
}

func (tx *LegacyTransaction) SendRaw(client *rpc.Client, ctx context.Context, rawTxHex string) (string, error) {
	err := client.CallContext(ctx, &tx.txHash, "eth_sendRawTransaction", rawTxHex)
	if err != nil {
		return "", fmt.Errorf("transaction transfer failed: %v", err)
	}
	return tx.txHash.Hex(), nil
}

// Confirm waits until the transaction receives the specified number of block confirmations
func (tx *LegacyTransaction) Confirm(ctx context.Context, blockConfirmations uint64) (*types.Receipt, error) {
	if tx.txHash == (common.Hash{}) {
		return nil, fmt.Errorf("Must send the transaction first")
	}

	// Check for first receipt
	var receipt *types.Receipt
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			r, err := tx.client.TransactionReceipt(ctx, tx.txHash)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}
			receipt = r
			break
		}
		break
	}

	fmt.Printf("Transaction included in block %d.\n", receipt.BlockNumber.Uint64())

	// Wait until desired number of block confirmations
	if blockConfirmations > 0 {
		targetBlock := new(big.Int).Add(receipt.BlockNumber, new(big.Int).SetUint64(blockConfirmations))
		
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				header, err := tx.client.HeaderByNumber(ctx, nil)
				if err != nil {
					time.Sleep(2 * time.Second)
					continue
				}
				
				// Check if target block has been reached
				if header.Number.Cmp(targetBlock) >= 0 {
					confirmations := new(big.Int).Sub(header.Number, receipt.BlockNumber).Uint64()
					fmt.Printf("Transaction has received %d confirmations.\n", confirmations)
					receiptAsJson, err := json.MarshalIndent(receipt, "", "  ")
					if err !=nil {
						return nil, fmt.Errorf("Failed to convert receipt to json type")
					}
					fmt.Println(string(receiptAsJson))
					
					return receipt, nil
				}
				
				time.Sleep(2 * time.Second)
			}
		}
	}
	
	return receipt, nil
}