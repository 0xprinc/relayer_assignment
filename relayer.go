package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
)

// Global variables for the relayer
var (
	clientA       *ethclient.Client      // Client connection to Network A
	clientB       *ethclient.Client      // Client connection to Network B
	privateKey    *ecdsa.PrivateKey      // Relayer's private key for signing transactions
	contractAAddr common.Address         // Address of the contract on Network A
	contractBAddr common.Address         // Address of the contract on Network B
	relayerAddr   common.Address         // Address of the relayer account
	contractAABI  abi.ABI                // ABI of Contract A
	contractBABI  abi.ABI                // ABI of Contract B
	chainIDA      = big.NewInt(84532)    // Chain ID for Network A (Base Goerli)
	chainIDB      = big.NewInt(11155111) // Chain ID for Network B (Sepolia)
)

// main function initializes the relayer and starts listening for events
func main() {
	// Load environment variables from .env file
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file: ", err)
	}

	// Establish connection to Network A
	clientA, err = ethclient.Dial(os.Getenv("NETWORK_A_RPC"))
	if err != nil {
		log.Fatalf("Failed to connect to network A: %v", err)
	}

	// Establish connection to Network B
	clientB, err = ethclient.Dial(os.Getenv("NETWORK_B_RPC"))
	if err != nil {
		log.Fatalf("Failed to connect to network B: %v", err)
	}

	blockNumber, err := clientA.BlockNumber(context.Background())
	if err != nil {
		log.Fatalf("Failed to get block number for chain A: %v", err)
	}
	fmt.Println("chainA Block Number", blockNumber)

	blockNumber, err = clientB.BlockNumber(context.Background())
	if err != nil {
		log.Fatalf("Failed to get block number for chain A: %v", err)
	}
	fmt.Println("chainB Block Number", blockNumber)

	// Parse contract addresses from environment variables
	contractAAddr = common.HexToAddress(os.Getenv("CONTRACT_A"))
	contractBAddr = common.HexToAddress(os.Getenv("CONTRACT_B"))

	// Load and decrypt the relayer's private key
	privateKey, err = loadPrivateKey(os.Getenv("RELAYER_PRIVATE_KEY"))
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	// Parse the contract ABIs from environment variables
	contractAABI, err = abi.JSON(strings.NewReader(os.Getenv("CONTRACT_A_ABI")))
	if err != nil {
		log.Fatalf("Failed to parse Contract A ABI: %v", err)
	}

	contractBABI, err = abi.JSON(strings.NewReader(os.Getenv("CONTRACT_B_ABI")))
	if err != nil {
		log.Fatalf("Failed to parse Contract B ABI: %v", err)
	}

	// Start event listeners in separate goroutines
	go listenSynEvent()    // Listen for SynSent events on Network A
	go listenAckEvent()    // Listen for AckSent events on Network B
	go listenSynAckEvent() // Listen for SynAckSent events on Network A

	// Keep the relayer running indefinitely
	select {}
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

	// Set the relayer address
	relayerAddr = crypto.PubkeyToAddress(privateKey.PublicKey)

	return privateKey, nil
}

// listenSynEvent listens for SynSent events on Contract A and relays them to Contract B
func listenSynEvent() {
	// Get the latest block number
	latestBlock, err := clientA.BlockNumber(context.Background())
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}
	fmt.Printf("Starting to listen for SynSent events from block %d\n", latestBlock)

	delay := time.Second * 1 // Fixed 1 second delay

	// Create event signature for SynSent
	synSentEvent := contractAABI.Events["SynSent"]
	synSentTopic := synSentEvent.ID

	// Keep track of processed event hashes
	processedEvents := make(map[string]bool)

	for {
		// Get current block number
		currentBlock, err := clientA.BlockNumber(context.Background())
		if err != nil {
			log.Printf("Error getting current block: %v", err)
			time.Sleep(delay)
			continue
		}

		// If we're behind, process all blocks up to current
		if currentBlock > latestBlock {
			// Get logs from all blocks up to current
			logs, err := clientA.FilterLogs(context.Background(), ethereum.FilterQuery{
				FromBlock: big.NewInt(int64(latestBlock)),
				ToBlock:   big.NewInt(int64(currentBlock)),
				Addresses: []common.Address{contractAAddr},
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
				sendTransaction(clientB, contractBAddr, "receiveSyn")

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
func listenAckEvent() {
	// Get the latest block number
	latestBlock, err := clientB.BlockNumber(context.Background())
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}
	fmt.Printf("Starting to listen for AckSent events from block %d\n", latestBlock)

	delay := time.Second * 1 // Fixed 1 second delay

	// Create event signature for AckSent
	ackSentEvent := contractBABI.Events["AckSent"]
	ackSentTopic := ackSentEvent.ID

	// Keep track of processed event hashes
	processedEvents := make(map[string]bool)

	for {
		// Get current block number
		currentBlock, err := clientB.BlockNumber(context.Background())
		if err != nil {
			log.Printf("Error getting current block: %v", err)
			time.Sleep(delay)
			continue
		}

		// If we're behind, process all blocks up to current
		if currentBlock > latestBlock {
			// Get logs from all blocks up to current
			logs, err := clientB.FilterLogs(context.Background(), ethereum.FilterQuery{
				FromBlock: big.NewInt(int64(latestBlock)),
				ToBlock:   big.NewInt(int64(currentBlock)),
				Addresses: []common.Address{contractBAddr},
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
				sendTransaction(clientA, contractAAddr, "receiveAck")

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
func listenSynAckEvent() {
	// Get the latest block number
	latestBlock, err := clientA.BlockNumber(context.Background())
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}
	fmt.Printf("Starting to listen for SynAckSent events from block %d\n", latestBlock)

	delay := time.Second * 1 // Fixed 1 second delay

	// Create event signature for SynAckSent
	synAckSentEvent := contractAABI.Events["SynAckSent"]
	synAckSentTopic := synAckSentEvent.ID

	// Keep track of processed event hashes
	processedEvents := make(map[string]bool)

	for {
		// Get current block number
		currentBlock, err := clientA.BlockNumber(context.Background())
		if err != nil {
			log.Printf("Error getting current block: %v", err)
			time.Sleep(delay)
			continue
		}

		// If we're behind, process all blocks up to current
		if currentBlock > latestBlock {
			// Get logs from all blocks up to current
			logs, err := clientA.FilterLogs(context.Background(), ethereum.FilterQuery{
				FromBlock: big.NewInt(int64(latestBlock)),
				ToBlock:   big.NewInt(int64(currentBlock)),
				Addresses: []common.Address{contractAAddr},
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
				sendTransaction(clientB, contractBAddr, "receiveSynAck")

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
func sendTransaction(client *ethclient.Client, contract common.Address, method string) {
	// Check if relayer address is set
	if relayerAddr == (common.Address{}) {
		log.Fatal("Relayer address not initialized")
	}

	// Get the current nonce for the relayer account
	nonce, err := client.NonceAt(context.Background(), relayerAddr, nil)
	if err != nil {
		log.Printf("Failed to get nonce: %v", err)
		return
	}

	// Select the appropriate ABI and chain ID based on the contract address
	var contractABI abi.ABI
	var chainID *big.Int
	if contract == contractAAddr {
		contractABI = contractAABI
		chainID = chainIDA
	} else if contract == contractBAddr {
		contractABI = contractBABI
		chainID = chainIDB
	} else {
		log.Printf("Unknown contract address: %s", contract.Hex())
		return
	}

	// Pack the function call data
	data, err := contractABI.Pack(method)
	if err != nil {
		log.Printf("Failed to pack function call: %v", err)
		return
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
		signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
		if err != nil {
			log.Printf("Failed to sign transaction: %v", err)
			return
		}

		// Send the transaction to the network
		err = client.SendTransaction(context.Background(), signedTx)
		if err != nil {
			if strings.Contains(err.Error(), "nonce too low") {
				// Get the latest nonce again and retry
				nonce, err = client.NonceAt(context.Background(), relayerAddr, nil)
				if err != nil {
					log.Printf("Failed to get nonce on retry: %v", err)
					return
				}
				log.Printf("Retrying with new nonce: %d", nonce)
				continue
			}
			log.Printf("Failed to send transaction: %v", err)
			return
		}

		// Print transaction details
		fmt.Printf("\nTransaction submitted:\n")
		fmt.Printf("Hash: %s\n", signedTx.Hash().Hex())
		fmt.Printf("From: %s\n", relayerAddr.Hex())
		fmt.Printf("To: %s\n", contract.Hex())
		fmt.Printf("Nonce: %d\n", nonce)
		fmt.Printf("Gas Price: %s wei\n", gasPrice.String())
		fmt.Printf("Gas Limit: %d\n", gasLimit)
		fmt.Printf("Method: %s\n", method)
		fmt.Printf("Data: %x\n", data)
		fmt.Printf("Chain ID: %s\n", chainID.String())
		fmt.Println("----------------------------------------\n")
		return
	}

	log.Printf("Failed to send transaction after %d retries", maxRetries)
}
