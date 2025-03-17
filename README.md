# Cross-Chain Two-Way Handshake System

This project implements a two-way handshake mechanism between smart contracts deployed on different blockchain networks (Base Sepolia and Sepolia) using a Go-based relayer service.

## Overview

The system implements a three-step handshake process between two smart contracts:
1. **SYN**: Contract A initiates the handshake by sending a SYN message to Contract B
2. **ACK**: Contract B responds to the SYN message by sending an ACK back to Contract A
3. **SYN-ACK**: Contract A confirms receipt of the ACK by sending a SYN-ACK to Contract B

The handshake is facilitated by a relayer service that listens for events on both chains and relays messages between the contracts.

## Architecture

### Smart Contracts
- **Contract A**: Deployed on Base Goerli (Chain ID: 84532)
- **Contract B**: Deployed on Sepolia (Chain ID: 11155111)

### Relayer Service
- Written in Go
- Listens for events on both chains simultaneously
- Handles transaction signing and submission
- Implements retry logic for failed transactions
- Prevents duplicate event processing

## Prerequisites

- Go 1.16 or higher
- Contract A is in Base Sepolia and Contract B is in Sepolia
- Test ETH on both networks for gas fees
- A private key for the relayer account

## Configuration

1. Create a `.env` file in the project root with the following variables:
```env
# Network RPC URLs
NETWORK_A_RPC=https://sepolia.base.org
NETWORK_B_RPC=https://rpc.sepolia.ethpandaops.io

# Contract Addresses
CONTRACT_A=0x...  # Base Sepolia contract address
CONTRACT_B=0x...  # Sepolia contract address

# Contract ABIs
CONTRACT_A_ABI=[...]  # JSON array of Contract A ABI
CONTRACT_B_ABI=[...]  # JSON array of Contract B ABI

# Relayer Configuration
RELAYER_PRIVATE_KEY=0x...  # Private key for the relayer account
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd relayer_project
```

2. Install dependencies:
```bash
go mod download
```

3. Configure your environment:
```bash
cp .env.example .env
# Edit .env with your values
```

## Usage

1. Start the relayer:
```bash
go run relayer.go
```

The relayer will:
- Connect to both networks
- Start listening for events
- Print the current block numbers on both chains
- Begin processing events and relaying messages

## Error Handling

The system includes several error handling mechanisms:
- Retry logic for failed transactions
- Nonce management for transaction ordering
- Duplicate event detection
- Network connection error handling
- Gas estimation fallbacks

## Monitoring

The relayer provides detailed logging:
- Transaction submission details
- Event detection
- Error messages
- Network status updates