# 🛡️ Stealth Payment System CLI

## 📖 Overview

The **Stealth Payment System CLI** provides a secure and private escrow mechanism for **Ethereum (ETH) transactions**. The system allows **senders to deposit ETH** into a smart contract without directly linking it to the receiver. **Zero-Knowledge Proofs (ZK-SNARKs)** ensure **privacy and security**, preventing double-spending and making transactions unlinkable.

## ✨ Key Features

- **🔑 Stealth Addresses** – Unique, per-transaction addresses hide recipient identity.
- **🛡️ Zero-Knowledge Proofs** – Uses zk-SNARKs for secure and anonymous fund claims.
- **💰 Anonymous Payments** – No direct on-chain link between sender and receiver.
- **⚡ CLI Interface** – Lightweight command-line interface for seamless interaction.

---

## 🏗️ System Architecture

### 🔹 **Smart Contracts**
- **Carrier Contract** – Registers recipient public keys.
- **Escrow Contract** – Manages deposits and claims using commitments and ZK-SNARK proofs.

### 🔹 **Cryptographic Components**
- **Commitment** – A cryptographic hash that binds the deposit to a **shared secret** without revealing it.
- **Shared Secret** – Derived using **Elliptic Curve Diffie-Hellman (ECDH)** between sender and receiver.
- **Nullifier** – A unique value ensuring **each deposit can only be claimed once**.
- **ZK-SNARK Proof** – Receiver proves knowledge of the **shared secret** without revealing it.

---

## 🔑 Privacy & Security Features

✔ **No Link Between Sender & Receiver**  
✔ **Prevents Double-Spending with Nullifiers**  
✔ **Each Transaction Uses a Unique Ephemeral Key**  
✔ **Zero-Knowledge Proofs Ensure Private Fund Claims**  

---

## 🔄 **Deposit Process**

1️⃣ **Retrieve Receiver's Public Key**  
   - The sender fetches the recipient’s registered public key (`pub_r`) from the Carrier Contract.  

2️⃣ **Generate Ephemeral Key Pair**  
   - The sender creates an ephemeral key pair:  
     ```math
     eph\_pub = eph\_priv \times G
     ```
   - This ensures that each deposit is uniquely linked to the sender.

3️⃣ **Compute Shared Secret (ECDH)**  
   - The sender computes the shared secret:
     ```math
     shared = eph\_priv \times pub_r
     ```
   - The receiver **can later compute the same shared secret** using their private key.

4️⃣ **Compute Hashed Secret**  
   - The sender hashes the shared secret:
     ```math
     hashedSecret = poseidon.hash(sharedSecretX)
     ```

5️⃣ **Compute Stealth Public Key**
   - The stealth public key is computed as:
     ```math
     pub\_once = hash(shared) \times G + pub_r
     ```
   - This ensures only the receiver can derive the corresponding private key.

6️⃣ **Compute Commitment & Deposit Transaction**  
   - The **commitment** is stored in the Escrow Contract:
     ```math
     commitment = poseidon.hash(hashedSecret)
     ```
   - The sender deposits funds by calling:
     ```sh
     bun cli.ts deposit -r <recipient-address> -a <amount>
     ```

---

## 🔓 **Claim Process**

1️⃣ **Receiver Identifies the Deposit**  
   - Uses their private key to **compute the same shared secret**.  

2️⃣ **Compute Hashed Secret & Commitment**  
   - Ensures that the computed **commitment matches** the one stored on-chain.  

3️⃣ **Compute Nullifier**  
   - To prevent double-spending:
     ```math
     depositNullifier = poseidon.hash([computedCommitment, safeSharedSecret])
     ```

4️⃣ **Generate ZK-SNARK Proof**  
   - Proves knowledge of the **shared secret** without revealing it.

5️⃣ **Submit Claim Transaction**  
   - The receiver submits:
     ```sh
     bun cli.ts claim
     ```

---

## 🛠 Prerequisites

✅ **[Bun](https://bun.sh/) installed**  
✅ **Node.js v18+**  
✅ **Ethereum-compatible wallet with ETH for gas**  
✅ **Access to an Ethereum RPC endpoint**  
✅ **[snarkjs](https://github.com/iden3/snarkjs) for zk-SNARK proof generation**  

---

## 🚀 Installation

```sh
# Clone the repository
git clone https://github.com/ngmachado/stealth-payment-cli
cd stealth-payment-cli

# Install dependencies
bun install

# Add execution permission (optional)
chmod +x cli.ts
```

---

## 💻 CLI Usage Guide

### 🔹 1️⃣ Setup & Wallet Configuration
```sh
bun cli.ts setup
```
🔑 **Inputs required:**
- Encryption password (secure storage)
- Private key (for signing transactions)
- Ethereum RPC URL

---

### 🔹 2️⃣ Register Public Key
```sh
bun cli.ts register
```
📡 Registers your **public key** on-chain (required for receiving funds).

---

### 🔹 3️⃣ Deposit ETH to a Stealth Address
```sh
bun cli.ts deposit -r <recipient-address> -a <amount>
```
Example:
```sh
bun cli.ts deposit -r 0x1234...5678 -a 0.5
```
---

### 🔹 4️⃣ Scan for Incoming Deposits
```sh
bun cli.ts scan
```

---

## ⚠️ Security Considerations

✔ **Keep private keys secure & never share them**  
✔ **Use a strong encryption password during setup**  
✔ **Consider using a private RPC endpoint to prevent metadata leakage**  
✔ **This is experimental software – use at your own risk**  

---

## 🔒 Privacy Enhancements

✔ **Zero-knowledge proofs** ensure claim privacy  
✔ **Ephemeral keys** prevent on-chain linking  
✔ **Stealth addresses** mask recipient identity  
✔ **ECDH key exchange** secures communication  

---

## 📜 License
This project is licensed under the **MIT License**.

---

## ⚠️ Disclaimer
🚨 This is **experimental software** provided **as-is** without any warranty.  
🚨 **This codebase has NOT been audited** – use at your own risk!  

---

### **🔗 Useful Resources**
- [Bun Documentation](https://bun.sh/docs)
- [snarkjs Library](https://github.com/iden3/snarkjs)

---

🔥 **Stealth Payment System - Privacy-Preserving Crypto Payments** 🔥

