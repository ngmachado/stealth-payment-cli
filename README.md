# Stealth Payment System CLI

## 📖 Overview
This CLI tool enables **anonymous and secure transactions** using **stealth addresses** on EVM. It leverages **ephemeral key pairs**, **ECDH key exchange**, and **smart contracts** to allow users to send and receive funds privately.

- **Stealth Addresses:** Generates a unique stealth address for every transaction.
- **Anonymous Payments:** Ensures the sender and recipient identities are unlinkable.
- **Secure Claims:** Allows the recipient to claim funds without revealing their main address.
- **CLI Interface:** Provides an easy-to-use command-line interface for setup and transactions.

## 🛠 Prerequisites
Before using this CLI, ensure you have:

- [Bun](https://bun.sh/) installed
- Node.js **v18+** (Bun includes Node compatibility)
- An Ethereum-compatible wallet with some ETH for gas fees
- Access to an Ethereum RPC provider

## 🔧 Installation
```sh
# Clone the repository
git clone https://github.com/ngmachado/stealth-payment-cli
cd stealth-payment-cli

# Install dependencies
bun install
```

## 🚀 Getting Started

###  Add execution permission to the script if you want to run as ./cli.ts 
```sh
chmod +x cli.ts
```

### **1️⃣ Setup Wallet and Contracts**
This step encrypts and stores your private key securely.

```sh
bun cli.ts setup
```
**Inputs:**
- 🔑 Encryption password (for secure storage)
- 🔐 Private key (used to sign transactions)
- 🌐 Ethereum RPC URL


### **2️⃣ Register Your Public Key**
To receive funds, register your **public key** on-chain.

```sh
bun cli.ts register
```


### **3️⃣ Generate a Stealth Address**
Before sending funds, you must generate a **stealth address** for the recipient.

```sh
bun cli.ts generate -r <recipient-address>
```
Example:
```sh
bun cli.ts generate -r 0x1234...5678
```


### **4️⃣ Send Funds Anonymously**
Transfer ETH to a **stealth address**.

```sh
bun cli.ts send -r <recipient-address> -a <amount>
```
Example:
```sh
bun cli.ts send -r 0x1234...5678 -a 0.5
```


### **5️⃣ Scan for Unclaimed Deposits**
Check for claimable funds linked to your wallet.

```sh
bun cli.ts scan
```


### **6️⃣ Claim Funds**
Claim ETH from a **stealth address** and transfer it to your wallet.

```sh
bun cli.ts claim -s <stealth-address> -e <ephemeral-pubkey>
```
Example:
```sh
bun cli.ts claim -s 0x5678...1234 -e 0xabcd...efgh
```

## ⚠️ Security Considerations
- **Never share your private key.** Store it securely.
- **Use a strong password** during `setup` to protect your encrypted credentials.
- **Avoid reusing stealth addresses.** Each transaction should generate a new one.
- **Use a private RPC provider** to avoid leaking metadata.

## 📜 License
This project is open-source under the MIT License.

## 🛠 Future Enhancements
- **Ephemeral Key Encryption:** To prevent on-chain tracking.
- **Zero-Knowledge Proofs:** To remove reliance on public key submission.
- **Decentralized Relayers:** To mitigate front-running risks.

## Notice
This project is a work in progress and is not audited. Use at your own risk. I'm a monkey with a keyboard.

