#!/usr/bin/env bun

import { program } from "commander";
import inquirer from "inquirer";
import { ethers } from "ethers";
import * as secp from "@noble/curves/secp256k1";
import chalk from "chalk";
import { encryptConfig, decryptConfig } from "./encryption";
import { execSync } from "child_process";
import fs from "fs";
import { poseidon } from "@iden3/js-crypto";

const FIELD_SIZE = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const VERBOSE = process.env.VERBOSE === "true";

// Contract ABIs
const CARRIER_ABI = [
    "function publishPublicKey(bytes calldata publicKey) external",
    "function getPublicKey(address user) external view returns (bytes)",
    "function hasPublicKey(address user) external view returns (bool)"
];

const ESCROW_ABI = [
    "function deposit(uint256 commitment, bytes calldata ephemeralPubKey) external payable",
    "function claim(uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c, uint256[2] calldata publicSignals, address recipient) external",
    "function commitments(uint256 commitment) external view returns (uint256)",
    "event EtherDeposited(uint256 commitment, uint256 amount, bytes ephemeralPubKey)",
    "function getStoredCommitment(uint256 commitment) external view returns (uint256)",
    "function getStoredAmount(uint256 commitment) external view returns (uint256)",
    "function hasCommitment(uint256 commitment) external view returns (bool)"
];

const CARRIER_ADDRESS = "0x1880FC712f90a4F3CfdA1401c0e254B4a164ED17";
const ESCROW_ADDRESS = "0x02a34BD67789f2DD08E4281eE6Ce3e9B1dF6b28a";

let provider: ethers.JsonRpcProvider;
let signer: ethers.Wallet;
let carrierContract: ethers.Contract;
let escrowContract: ethers.Contract;

// Add a safe logging utility
function safeLog(message: string, data?: any) {
    if (!VERBOSE) return;

    // Remove sensitive data if present
    const sanitizedData = data ? JSON.stringify(data, (key, value) => {
        if (['privateKey', 'secret', 'key', 'password'].includes(key.toLowerCase())) {
            return '***redacted***';
        }
        return value;
    }, 2) : '';

    console.log(chalk.gray(`🔍 ${message}`), sanitizedData ? `\n${sanitizedData}` : '');
}

async function setupContracts(): Promise<void> {
    const { privateKey, rpcUrl, password } = await inquirer.prompt([
        { type: "password", name: "password", message: "🔑 Enter encryption password:" },
        { type: "password", name: "privateKey", message: "🔐 Enter your private key:" },
        { type: "input", name: "rpcUrl", message: "🌐 Enter your RPC URL:" }
    ]);

    initializeContracts(privateKey, rpcUrl);
    encryptConfig({ privateKey, rpcUrl }, password);
}

async function initializeContracts(privateKey: string, rpcUrl: string): Promise<void> {
    try {
        provider = new ethers.JsonRpcProvider(rpcUrl);
        signer = new ethers.Wallet(privateKey, provider);
        carrierContract = new ethers.Contract(CARRIER_ADDRESS, CARRIER_ABI, signer);
        escrowContract = new ethers.Contract(ESCROW_ADDRESS, ESCROW_ABI, signer);
    } catch (error) {
        console.error(chalk.red("❌ Failed to initialize contracts:"), error);
        throw error;
    }
}

async function ensureSetup(): Promise<void> {
    const { password } = await inquirer.prompt([
        { type: "password", name: "password", message: "🔑 Enter encryption password:" }
    ]);
    const config = decryptConfig(password);
    if (!config) {
        console.error(chalk.red("❌ Setup required! Run `bun cli.ts setup`"));
        process.exit(1);
    }
    initializeContracts(config.privateKey, config.rpcUrl);
}

// Add type for proof result
interface ProofResult {
    proof: {
        pi_a: string[];
        pi_b: string[][];
        pi_c: string[];
    };
    publicSignals: string[];
}

async function generateProof(secret: string, commitment: string): Promise<ProofResult> {
    const tempInputPath = `input.json`;
    const tempProofPath = `proof.json`;
    const tempPublicPath = `public.json`;
    const tempWitnessPath = `witness.wtns`;

    try {
        const input = {
            secret: secret,          // Private input
            commitment: commitment   // Public input
        };

        console.log("Generating witness with inputs:", input);
        fs.writeFileSync(tempInputPath, JSON.stringify(input));

        // Generate witness file
        execSync(
            `node ../circuits/build/commitment_js/generate_witness.js ../circuits/build/commitment_js/commitment.wasm ${tempInputPath} ${tempWitnessPath}`
        );
        console.log("Witness generated");

        // Run zk-SNARK proof generation
        execSync(`snarkjs groth16 prove ../circuits/build/commitment_final.zkey ${tempWitnessPath} ${tempProofPath} ${tempPublicPath}`);
        console.log("Proof generated");

        // Read proof and public signals
        const proof = JSON.parse(fs.readFileSync(tempProofPath, "utf-8"));
        const publicSignals = JSON.parse(fs.readFileSync(tempPublicPath, "utf-8"));

        return { proof, publicSignals };
    } catch (error) {
        console.error(chalk.red("❌ Failed to generate proof:"), error);
        throw error; // Better to throw than exit
    } finally {
        // Enable file cleanup in production
        [tempInputPath, tempProofPath, tempPublicPath, tempWitnessPath].forEach(file => {
            if (fs.existsSync(file)) fs.unlinkSync(file);
        });
    }
}

// Update the event interface
interface EtherDepositedEvent extends ethers.Log {
    args: [bigint, bigint, string] & {
        commitment: bigint;
        amount: bigint;
        ephemeralPubKey: string;
    };
}

async function claimFunds(commitment: string, ephemeralPubKey: string): Promise<void> {
    console.log(chalk.blue("🔑 Claiming funds..."));
    const commitmentBigInt = BigInt(commitment);
    try {

        const { relayerKey, recipient } = await inquirer.prompt([
            { type: "password", name: "relayerKey", message: "🔑 Enter relayer private key:" },
            { type: "input", name: "recipient", message: "Enter recipient address:" }
        ]);

        // Validate recipient address
        if (!ethers.isAddress(recipient)) {
            throw new Error("❌ Invalid recipient address format");
        }

        // Use the relayer's account
        const relayer = new ethers.Wallet(relayerKey, provider);
        const relayerContract = new ethers.Contract(ESCROW_ADDRESS, ESCROW_ABI, relayer);

        // Get recipient's private key
        const recipientPrivateKey = signer.privateKey;

        const sharedSecret = secp.secp256k1.getSharedSecret(
            ethers.getBytes(recipientPrivateKey), // Receiver's private key
            ethers.getBytes(ephemeralPubKey),
            true // Return compressed public key
        );

        // Extract only the X-coordinate
        const sharedSecretX = BigInt("0x" + Buffer.from(sharedSecret.slice(1, 33)).toString("hex")) % FIELD_SIZE;

        // Use the sharedSecretX instead of raw sharedSecret
        const safeSharedSecret = poseidon.hash([sharedSecretX]);

        // Compute commitment (must match on-chain)
        const computedCommitment = poseidon.hash([safeSharedSecret]);  // Just hash the secret

        console.log("Computed Commitment:", computedCommitment.toString());
        console.log("Commitment:", commitmentBigInt.toString());
        console.log("Safe Shared Secret:", safeSharedSecret.toString());

        // Ensure commitment matches the provided one
        if (computedCommitment.toString() !== commitmentBigInt.toString()) {
            throw new Error("❌ Commitment mismatch! Derived commitment does not match the provided commitment.");
        }

        // Compute nullifier to prevent double-spending, % FIELD_SIZE
        const depositNullifier = poseidon.hash([computedCommitment, safeSharedSecret]);

        console.log("Computed Commitment:", computedCommitment.toString());
        console.log("Deposit Nullifier:", depositNullifier.toString());

        if (BigInt(safeSharedSecret) >= FIELD_SIZE || BigInt(depositNullifier) >= FIELD_SIZE || BigInt(commitment) >= FIELD_SIZE) {
            throw new Error("❌ One or more inputs exceed the SNARK field size!");
        }

        // Generate zk-SNARK proof
        const proofResult = await generateProof(
            safeSharedSecret.toString(),      // Private input: secret
            commitment.toString()             // Public input: commitment
        );

        const { proof, publicSignals } = proofResult;

        // Format proof points - ensure correct order and format
        const proofForContract = {
            pi_a: [
                ethers.hexlify(ethers.toBeArray(BigInt(proof.pi_a[0]))),
                ethers.hexlify(ethers.toBeArray(BigInt(proof.pi_a[1]))),
            ],
            pi_b: [
                [
                    ethers.hexlify(ethers.toBeArray(BigInt(proof.pi_b[0][1]))), // Note: B points need to be swapped
                    ethers.hexlify(ethers.toBeArray(BigInt(proof.pi_b[0][0]))),
                ],
                [
                    ethers.hexlify(ethers.toBeArray(BigInt(proof.pi_b[1][1]))),
                    ethers.hexlify(ethers.toBeArray(BigInt(proof.pi_b[1][0]))),
                ],
            ],
            pi_c: [
                ethers.hexlify(ethers.toBeArray(BigInt(proof.pi_c[0]))),
                ethers.hexlify(ethers.toBeArray(BigInt(proof.pi_c[1]))),
            ],
        };

        // Format for contract call
        const proofA = [proof.pi_a[0], proof.pi_a[1]];
        const proofB = [
            [proof.pi_b[0][1], proof.pi_b[0][0]], // Swap these points
            [proof.pi_b[1][1], proof.pi_b[1][0]], // Swap these points
        ];
        const proofC = [proof.pi_c[0], proof.pi_c[1]];

        console.log("\nFormatted Proof for Contract:");
        console.log("A:", proofA);
        console.log("B:", proofB);
        console.log("C:", proofC);
        console.log("Public Signals:", publicSignals);

        // Submit to contract
        const tx = await relayerContract.claim(
            proofA,
            proofB,
            proofC,
            publicSignals,
            recipient
        );

        console.log(chalk.yellow("⌛ Transaction pending..."), tx.hash);
        await tx.wait();

        console.log(chalk.green("✅ Funds claimed successfully!"));
    } catch (error) {
        console.error(chalk.red("❌ Error claiming funds:"), error);
        process.exit(1);
    }
}

async function scanDeposits(): Promise<void> {
    await ensureSetup();
    const filter = escrowContract.filters.EtherDeposited();
    const events = (await escrowContract.queryFilter(filter, -10000)) as EtherDepositedEvent[];
    if (events.length === 0) {
        console.log(chalk.yellow("⚠️ No claimable deposits found."));
        return;
    }
    const { depositIndex } = await inquirer.prompt([
        {
            type: "list",
            name: "depositIndex",
            message: "Which deposit would you like to claim?",
            choices: events.map((event, i) => ({
                name: `ETH: ${ethers.formatEther(event.args.amount)} at ${event.args.commitment} with ephemeral key ${event.args.ephemeralPubKey}`,
                value: i
            }))
        }
    ]);
    const deposit = events[depositIndex].args;
    await claimFunds(deposit.commitment.toString(), deposit.ephemeralPubKey);
}

async function depositETH(recipient: string, amount: string): Promise<void> {
    await ensureSetup();
    safeLog("Starting ETH deposit process", { recipient, amount });

    // 🔹 Step 1: Retrieve Recipient's Public Key
    const recipientPublicKey = await carrierContract.getPublicKey(recipient);
    safeLog("Retrieved recipient's public key");

    // 🔹 Step 2: Generate Ephemeral Key Pair
    const ephemeralPrivateKey = secp.secp256k1.utils.randomPrivateKey();
    safeLog("Generated ephemeral keypair");

    const ephemeralPublicKey = secp.secp256k1.getPublicKey(ephemeralPrivateKey, true);
    const recipientPubKeyBytes = ethers.getBytes(recipientPublicKey);

    // 🔹 Step 3: Compute Shared Secret (ECDH)
    const sharedSecret = secp.secp256k1.getSharedSecret(
        ephemeralPrivateKey,  // Sender's ephemeral private key
        recipientPubKeyBytes,  // Receiver's registered public key
        true                  // Return compressed public key
    );

    // Extract only the X-coordinate from the shared secret
    const sharedSecretX = BigInt("0x" + Buffer.from(sharedSecret.slice(1, 33)).toString("hex")) % FIELD_SIZE;

    // Compute Stealth Public Key
    const hashedSecret = poseidon.hash([sharedSecretX]); // Secure hashing function

    // Compute pub_once = hash(shared) * G + pub_r
    const stealthPubKey = secp.secp256k1.ProjectivePoint.BASE.multiply(hashedSecret)
        .add(secp.secp256k1.ProjectivePoint.fromHex(recipientPublicKey.slice(2))) // Remove 0x prefix
        .toRawBytes(true);

    // Compute the Ethereum address of the stealth public key
    const stealthAddress = ethers.getAddress(
        ethers.keccak256(ethers.hexlify(stealthPubKey)).slice(26) // Take last 20 bytes
    );
    safeLog("Computed stealth address", { stealthAddress });

    // Compute Commitment for Deposit
    const commitment = poseidon.hash([hashedSecret]);  // Matching circuit commitment
    safeLog("Computing commitment", { commitment: commitment.toString() });

    // Execute Transaction
    const tx = await escrowContract.deposit(commitment, ephemeralPublicKey, {
        value: ethers.parseEther(amount)
    });

    safeLog("Transaction sent", { hash: tx.hash });

    // Verify Deposit
    console.log("Checking stored amount...");
    const storedAmount = await escrowContract.getStoredAmount(commitment);
    console.log("Stored amount:", ethers.formatEther(storedAmount), "ETH");

    const exists = await escrowContract.hasCommitment(commitment);
    console.log("Commitment exists:", exists);

    console.log(chalk.green("✅ Deposit completed!"));
}

async function registerPublicKey(): Promise<void> {
    await ensureSetup();

    try {
        console.log(chalk.blue("🔹 Generating public key..."));
        const privateKeyBytes = ethers.getBytes(signer.privateKey);
        const publicKey = secp.secp256k1.getPublicKey(privateKeyBytes, true);

        console.log(chalk.blue("\n📡 Registering public key on-chain..."));
        const tx = await carrierContract.publishPublicKey(publicKey);
        console.log(chalk.yellow("⌛ Transaction pending..."), tx.hash);
        await tx.wait();

        console.log(chalk.green("✅ Public key registered successfully!"));

        // verify registration
        const registeredKey = await carrierContract.getPublicKey(await signer.getAddress());
        console.log("\nVerification:");
        console.log("Registered Public Key:", registeredKey);
        console.log("Matches original:", registeredKey === ethers.hexlify(publicKey));
    } catch (error) {
        console.error(chalk.red("❌ Failed to register public key:"), error);
        if (error instanceof Error) {
            console.error(chalk.red("Error details:"), error.message);
        }
    }
}

program.command("setup").description("Setup wallet and contracts securely").action(setupContracts);
program.command("claim")
    .description("Claim funds using zk-SNARK proof")
    .requiredOption("-s, --stealthAddress <address>", "Stealth address to claim from")
    .requiredOption("-e, --ephemeralKey <key>", "Ephemeral public key")
    .action(async (options) => {
        await claimFunds(options.stealthAddress, options.ephemeralKey);
    });
program.command("scan").description("Scan for deposits that can be claimed").action(scanDeposits);
program.command("deposit")
    .description("Deposit ETH using zk-SNARK commitments")
    .requiredOption("-r, --recipient <address>", "Recipient address")
    .requiredOption("-a, --amount <amount>", "Amount in ETH")
    .action(async (options) => { await depositETH(options.recipient, options.amount); });
program.command("register")
    .description("Register your public key on-chain")
    .action(registerPublicKey);
program
    .option('-v, --verbose', 'Enable verbose logging')
    .hook('preAction', () => {
        if (program.opts().verbose) {
            process.env.VERBOSE = "true";
        }
    });
program.parse(process.argv);

