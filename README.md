# Stealth Payment System CLI

## 📖 Overview
This CLI tool enables **anonymous and secure transactions** using **stealth addresses** and **zero-knowledge proofs** on EVM. It leverages **ephemeral key pairs**, **ECDH key exchange**, and **smart contracts** to allow users to send and receive funds privately.

### Key Features
- **Stealth Addresses:** Generates unique stealth addresses for each transaction
- **Zero-Knowledge Proofs:** Uses zk-SNARKs for secure fund claims
- **Anonymous Payments:** Ensures sender and recipient identities are unlinkable
- **CLI Interface:** Simple command-line interface for all operations

## 🛠 Prerequisites
- [Bun](https://bun.sh/) installed
- Node.js v18 or higher
- An Ethereum-compatible wallet with ETH for gas
- Access to an Ethereum RPC endpoint
- [snarkjs](https://github.com/iden3/snarkjs) for zero-knowledge proof generation

## 🔧 Installation
```sh
# Clone the repository
git clone https://github.com/ngmachado/stealth-payment-cli
cd stealth-payment-cli

# Install dependencies
bun install

# Add execution permission (optional)
chmod +x cli.ts
```

## 🚀 Usage Guide

### 1. Initial Setup
Configure your wallet and encrypt credentials:
```sh
bun cli.ts setup
```
**Inputs:**
- 🔑 Encryption password (for secure storage)
- 🔐 Private key (used to sign transactions)
- �� Ethereum RPC URL

### 2. Register Public Key
Register your public key on-chain (required to receive funds):
```sh
bun cli.ts register
```

### 3. Deposit Funds
Send ETH to a recipient's address:
```sh
bun cli.ts deposit -r <recipient-address> -a <amount>
```
Example:
```sh
bun cli.ts deposit -r 0x1234...5678 -a 0.5
```

### 4. Scan for Deposits
Check for incoming deposits:
```sh
bun cli.ts scan
```

## ⚠️ Security Considerations
- Keep your private keys secure and never share them
- Use a strong encryption password during setup
- Consider using a private RPC endpoint to prevent metadata leakage
- This is experimental software - use at your own risk

## 🔒 Privacy Features
- Zero-knowledge proofs ensure claim privacy
- Ephemeral keys prevent on-chain linking
- Stealth addresses mask recipient identity
- ECDH key exchange for secure communication

## 📜 License
MIT License

## ⚠️ Disclaimer
This is experimental software provided as-is without warranty. The codebase has not been audited - use at your own risk.

