package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
)

// RelayerConfig holds the configuration for the relayer
type RelayerConfig struct {
	ClientA       *ethclient.Client
	ClientB       *ethclient.Client
	PrivateKey    *ecdsa.PrivateKey
	ContractAAddr common.Address
	ContractBAddr common.Address
	RelayerAddr   common.Address
	ContractAABI  abi.ABI
	ContractBABI  abi.ABI
	ChainIDA      *big.Int
	ChainIDB      *big.Int
}

// EventProcessor handles event processing and transaction sending
type EventProcessor struct {
	config *RelayerConfig
	mu     sync.Mutex
}

// NewEventProcessor creates a new event processor
func NewEventProcessor(config *RelayerConfig) *EventProcessor {
	return &EventProcessor{
		config: config,
	}
}

// Global variables for the relayer
var (
	config *RelayerConfig
)

// main function initializes the relayer and starts listening for events
func main() {
	// Load environment variables from .env file
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file: ", err)
	}

	// Initialize configuration
	config, err = initializeConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	// Create event processor
	processor := NewEventProcessor(config)

	// Start event listeners in separate goroutines with error handling
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		if err := processor.listenSynEvent(); err != nil {
			log.Printf("Error in SynEvent listener: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := processor.listenAckEvent(); err != nil {
			log.Printf("Error in AckEvent listener: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := processor.listenSynAckEvent(); err != nil {
			log.Printf("Error in SynAckEvent listener: %v", err)
		}
	}()

	// Keep the relayer running indefinitely
	select {}
}

// initializeConfig initializes the relayer configuration
func initializeConfig() (*RelayerConfig, error) {
	// Establish connection to Network A
	clientA, err := ethclient.Dial(os.Getenv("NETWORK_A_RPC"))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to network A: %v", err)
	}

	// Establish connection to Network B
	clientB, err := ethclient.Dial(os.Getenv("NETWORK_B_RPC"))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to network B: %v", err)
	}

	// Parse contract addresses
	contractAAddr := common.HexToAddress(os.Getenv("CONTRACT_A"))
	contractBAddr := common.HexToAddress(os.Getenv("CONTRACT_B"))

	// Load private key
	privateKey, err := loadPrivateKey(os.Getenv("RELAYER_PRIVATE_KEY"))
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}

	// Parse contract ABIs
	contractAABI, err := abi.JSON(strings.NewReader(os.Getenv("CONTRACT_A_ABI")))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Contract A ABI: %v", err)
	}

	contractBABI, err := abi.JSON(strings.NewReader(os.Getenv("CONTRACT_B_ABI")))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Contract B ABI: %v", err)
	}

	return &RelayerConfig{
		ClientA:       clientA,
		ClientB:       clientB,
		PrivateKey:    privateKey,
		ContractAAddr: contractAAddr,
		ContractBAddr: contractBAddr,
		RelayerAddr:   crypto.PubkeyToAddress(privateKey.PublicKey),
		ContractAABI:  contractAABI,
		ContractBABI:  contractBABI,
		ChainIDA:      big.NewInt(84532),
		ChainIDB:      big.NewInt(11155111),
	}, nil
}

// loadPrivateKey converts a hex private key string to an ECDSA private key
func loadPrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	// Remove "0x" prefix if present
	hexKey = strings.TrimPrefix(hexKey, "0x")

	// Convert hex string to bytes
	privateKeyBytes := common.FromHex(hexKey)
	if len(privateKeyBytes) == 0 {
		return nil, fmt.Errorf("invalid private key hex")
	}

	// Convert bytes to private key using secp256k1 curve
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %v", err)
	}

	return privateKey, nil
}

// listenSynEvent listens for SynSent events on Contract A and relays them to Contract B
func (p *EventProcessor) listenSynEvent() error {
	// Get the latest block number
	latestBlock, err := p.config.ClientA.BlockNumber(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get latest block: %v", err)
	}
	fmt.Printf("Starting to listen for SynSent events from block %d\n", latestBlock)

	delay := time.Second * 1 // Fixed 1 second delay

	// Create event signature for SynSent
	synSentEvent := p.config.ContractAABI.Events["SynSent"]
	synSentTopic := synSentEvent.ID

	// Keep track of processed event hashes
	processedEvents := make(map[string]bool)

	for {
		// Get current block number
		currentBlock, err := p.config.ClientA.BlockNumber(context.Background())
		if err != nil {
			log.Printf("Error getting current block: %v", err)
			time.Sleep(delay)
			continue
		}

		// If we're behind, process all blocks up to current
		if currentBlock > latestBlock {
			// Get logs from all blocks up to current
			logs, err := p.config.ClientA.FilterLogs(context.Background(), ethereum.FilterQuery{
				FromBlock: big.NewInt(int64(latestBlock)),
				ToBlock:   big.NewInt(int64(currentBlock)),
				Addresses: []common.Address{p.config.ContractAAddr},
				Topics:    [][]common.Hash{{synSentTopic}},
			})
			if err != nil {
				log.Printf("Error getting logs: %v", err)
				time.Sleep(delay)
				continue
			}

			// Process logs
			for _, log := range logs {
				// Create a unique identifier for this event
				eventID := fmt.Sprintf("%s-%d", log.TxHash.Hex(), log.Index)

				// Skip if we've already processed this event
				if processedEvents[eventID] {
					continue
				}

				fmt.Println("SynSent event detected. Relaying to Contract B...")
				if err := p.sendTransaction(p.config.ClientB, p.config.ContractBAddr, "receiveSyn"); err != nil {
					fmt.Printf("Failed to send transaction: %v\n", err)
					continue
				}

				// Mark this event as processed
				processedEvents[eventID] = true
			}

			// Update latest block to current
			latestBlock = currentBlock
		}

		time.Sleep(delay)
	}
}

// listenAckEvent listens for AckSent events on Contract B and relays them to Contract A
func (p *EventProcessor) listenAckEvent() error {
	// Get the latest block number
	latestBlock, err := p.config.ClientB.BlockNumber(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get latest block: %v", err)
	}
	fmt.Printf("Starting to listen for AckSent events from block %d\n", latestBlock)

	delay := time.Second * 1 // Fixed 1 second delay

	// Create event signature for AckSent
	ackSentEvent := p.config.ContractBABI.Events["AckSent"]
	ackSentTopic := ackSentEvent.ID

	// Keep track of processed event hashes
	processedEvents := make(map[string]bool)

	for {
		// Get current block number
		currentBlock, err := p.config.ClientB.BlockNumber(context.Background())
		if err != nil {
			log.Printf("Error getting current block: %v", err)
			time.Sleep(delay)
			continue
		}

		// If we're behind, process all blocks up to current
		if currentBlock > latestBlock {
			// Get logs from all blocks up to current
			logs, err := p.config.ClientB.FilterLogs(context.Background(), ethereum.FilterQuery{
				FromBlock: big.NewInt(int64(latestBlock)),
				ToBlock:   big.NewInt(int64(currentBlock)),
				Addresses: []common.Address{p.config.ContractBAddr},
				Topics:    [][]common.Hash{{ackSentTopic}},
			})
			if err != nil {
				log.Printf("Error getting logs: %v", err)
				time.Sleep(delay)
				continue
			}

			// Process logs
			for _, log := range logs {
				// Create a unique identifier for this event
				eventID := fmt.Sprintf("%s-%d", log.TxHash.Hex(), log.Index)

				// Skip if we've already processed this event
				if processedEvents[eventID] {
					continue
				}

				fmt.Println("AckSent event detected. Relaying to Contract A...")
				if err := p.sendTransaction(p.config.ClientA, p.config.ContractAAddr, "receiveAck"); err != nil {
					fmt.Printf("Failed to send transaction: %v\n", err)
					continue
				}

				// Mark this event as processed
				processedEvents[eventID] = true
			}

			// Update latest block to current
			latestBlock = currentBlock
		}

		time.Sleep(delay)
	}
}

// listenSynAckEvent listens for SynAckSent events on Contract A and relays them to Contract B
func (p *EventProcessor) listenSynAckEvent() error {
	// Get the latest block number
	latestBlock, err := p.config.ClientA.BlockNumber(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get latest block: %v", err)
	}
	fmt.Printf("Starting to listen for SynAckSent events from block %d\n", latestBlock)

	delay := time.Second * 1 // Fixed 1 second delay

	// Create event signature for SynAckSent
	synAckSentEvent := p.config.ContractAABI.Events["SynAckSent"]
	synAckSentTopic := synAckSentEvent.ID

	// Keep track of processed event hashes
	processedEvents := make(map[string]bool)

	for {
		// Get current block number
		currentBlock, err := p.config.ClientA.BlockNumber(context.Background())
		if err != nil {
			log.Printf("Error getting current block: %v", err)
			time.Sleep(delay)
			continue
		}

		// If we're behind, process all blocks up to current
		if currentBlock > latestBlock {
			// Get logs from all blocks up to current
			logs, err := p.config.ClientA.FilterLogs(context.Background(), ethereum.FilterQuery{
				FromBlock: big.NewInt(int64(latestBlock)),
				ToBlock:   big.NewInt(int64(currentBlock)),
				Addresses: []common.Address{p.config.ContractAAddr},
				Topics:    [][]common.Hash{{synAckSentTopic}},
			})
			if err != nil {
				log.Printf("Error getting logs: %v", err)
				time.Sleep(delay)
				continue
			}

			// Process logs
			for _, log := range logs {
				// Create a unique identifier for this event
				eventID := fmt.Sprintf("%s-%d", log.TxHash.Hex(), log.Index)

				// Skip if we've already processed this event
				if processedEvents[eventID] {
					continue
				}

				fmt.Println("SynAckSent event detected. Relaying to Contract B...")
				if err := p.sendTransaction(p.config.ClientB, p.config.ContractBAddr, "receiveSynAck"); err != nil {
					fmt.Printf("Failed to send transaction: %v", err)
					continue
				}

				// Mark this event as processed
				processedEvents[eventID] = true
			}

			// Update latest block to current
			latestBlock = currentBlock
		}

		time.Sleep(delay)
	}
}

// sendTransaction creates and sends a transaction to the specified contract
func (p *EventProcessor) sendTransaction(client *ethclient.Client, contract common.Address, method string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if relayer address is set
	if p.config.RelayerAddr == (common.Address{}) {
		return fmt.Errorf("relayer address not initialized")
	}

	// Get the current nonce for the relayer account
	nonce, err := client.NonceAt(context.Background(), p.config.RelayerAddr, nil)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %v", err)
	}

	// Select the appropriate ABI and chain ID based on the contract address
	var contractABI abi.ABI
	var chainID *big.Int
	if contract == p.config.ContractAAddr {
		contractABI = p.config.ContractAABI
		chainID = p.config.ChainIDA
	} else if contract == p.config.ContractBAddr {
		contractABI = p.config.ContractBABI
		chainID = p.config.ChainIDB
	} else {
		return fmt.Errorf("unknown contract address: %s", contract.Hex())
	}

	// Pack the function call data
	data, err := contractABI.Pack(method)
	if err != nil {
		return fmt.Errorf("failed to pack function call: %v", err)
	}

	// Use fixed gas values
	gasLimit := uint64(100000)         // Fixed gas limit
	gasPrice := big.NewInt(1000000000) // 1 Gwei

	// Try to send transaction with retries
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		// Create new transaction
		tx := types.NewTransaction(
			nonce,
			contract,
			big.NewInt(0),
			gasLimit,
			gasPrice,
			data,
		)

		// Sign the transaction
		signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), p.config.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to sign transaction: %v", err)
		}

		// Send the transaction to the network
		err = client.SendTransaction(context.Background(), signedTx)
		if err != nil {
			if strings.Contains(err.Error(), "nonce too low") {
				// Get the latest nonce again and retry
				nonce, err = client.NonceAt(context.Background(), p.config.RelayerAddr, nil)
				if err != nil {
					return fmt.Errorf("failed to get nonce on retry: %v", err)
				}
				log.Printf("Retrying with new nonce: %d", nonce)
				continue
			}
			return fmt.Errorf("failed to send transaction: %v", err)
		}

		// Print transaction details
		fmt.Printf("\nTransaction submitted:\n")
		fmt.Printf("Hash: %s\n", signedTx.Hash().Hex())
		fmt.Printf("From: %s\n", p.config.RelayerAddr.Hex())
		fmt.Printf("To: %s\n", contract.Hex())
		fmt.Printf("Nonce: %d\n", nonce)
		fmt.Printf("Gas Price: %s wei\n", gasPrice.String())
		fmt.Printf("Gas Limit: %d\n", gasLimit)
		fmt.Printf("Method: %s\n", method)
		fmt.Printf("Data: %x\n", data)
		fmt.Printf("Chain ID: %s\n", chainID.String())
		fmt.Println("----------------------------------------\n")
		return nil
	}

	return fmt.Errorf("failed to send transaction after %d retries", maxRetries)
}
