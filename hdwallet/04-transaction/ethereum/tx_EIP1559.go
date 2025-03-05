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
)

// EIP1559Transaction structure
type EIP1559Transaction struct {
	client       *ethclient.Client
	privateKey   *ecdsa.PrivateKey
	to           common.Address
	value        *big.Int
	data         []byte
	nonce        uint64
	maxPriorityFeePerGas *big.Int
	maxFeePerGas *big.Int
	gasLimit     uint64
	chainID      *big.Int
	txHash       common.Hash
	v, r, s      *big.Int
}

// Return the transaction attributes
func (tx *EIP1559Transaction) To() common.Address {
	return tx.to
}
func (tx *EIP1559Transaction) Value() *big.Int {
	return tx.value
}
func (tx *EIP1559Transaction) Data() []byte {
	return tx.data
}
func (tx *EIP1559Transaction) Nonce() uint64 {
	return tx.nonce
}
func (tx *EIP1559Transaction) MaxPriorityFeePerGas() *big.Int {
	return tx.maxPriorityFeePerGas
}
func (tx *EIP1559Transaction) MaxFeePerGas() *big.Int {
	return tx.maxFeePerGas
}
func (tx *EIP1559Transaction) GasLimit() uint64 {
	return tx.gasLimit
}
func (tx *EIP1559Transaction) ChainID() *big.Int {
	return tx.chainID
}
func (tx *EIP1559Transaction) Hash() common.Hash {
	return tx.txHash
}

// NewEIP1559Transaction creates a new EIP-1559 transaction
func NewEIP1559Transaction(
	client *ethclient.Client,
	privateKeyHex string,
	toAddress string,
	value *big.Int,
	data []byte,
	gasLimit uint64,
) (*EIP1559Transaction, error) {
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
	gasTipCap, err := client.SuggestGasTipCap(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error getting gas tip cap: %w", err)
	}
	
	header, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("error getting baseFee: %w", err)
	}
	
	// 2 * baseFee + gasTipCap
	maxFeePerGas := new(big.Int).Add(
		new(big.Int).Mul(header.BaseFee, big.NewInt(2)),
		gasTipCap,
	)

	// Chain ID
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error getting chain id: %v", err)
	}

	return &EIP1559Transaction{
		client:       client,
		privateKey:   privateKey,
		to:           to,
		value:        value,
		data:         data,
		nonce:        nonce,
		maxPriorityFeePerGas: gasTipCap,
		maxFeePerGas: maxFeePerGas,
		gasLimit:     gasLimit,
		chainID:      chainID,
	}, nil
}

// Send broadcasts the transaction
func (tx *EIP1559Transaction) Send(ctx context.Context) (string, error) {
	// Create EIP-1559 transaction
	rawTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   tx.chainID,
		Nonce:     tx.nonce,
		GasTipCap: tx.maxPriorityFeePerGas,
		GasFeeCap: tx.maxFeePerGas,
		Gas:       tx.gasLimit,
		To:        &tx.to,
		Value:     tx.value,
		Data:      tx.data,
	})

	// Sign transaction
	signedTx, err := types.SignTx(rawTx, types.LatestSignerForChainID(tx.chainID), tx.privateKey)
	if err != nil {
		return "", fmt.Errorf("transaction signing error: %w", err)
	}

	// Send transaction
	err = tx.client.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("transaction sending error: %w", err)
	}
	tx.txHash = signedTx.Hash()
	tx.v, tx.r, tx.s = signedTx.RawSignatureValues()

	fmt.Println("transaction has been sent.")
	txAsJson, _ := json.MarshalIndent(signedTx, "", "  ")
	fmt.Println(string(txAsJson))
	
	return signedTx.Hash().Hex(), nil
}

// Confirm waits until the transaction receives the specified number of block confirmations
func (tx *EIP1559Transaction) Confirm(ctx context.Context, blockConfirmations uint64) (*types.Receipt, error) {
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
					receiptAsJson, _ := json.MarshalIndent(receipt, "", "  ")
					fmt.Println(string(receiptAsJson))
					
					return receipt, nil
				}
				
				time.Sleep(2 * time.Second)
			}
		}
	}
	
	return receipt, nil
}