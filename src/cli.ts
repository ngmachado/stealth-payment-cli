#!/usr/bin/env bun

import { program } from "commander";
import inquirer from "inquirer";
import { ethers } from "ethers";
import * as secp from "@noble/curves/secp256k1";
import chalk from "chalk";
import { encryptConfig, decryptConfig } from "./encryption";

// 🔹 Contract ABIs
const CARRIER_ABI = [
    "function publishPublicKey(bytes calldata publicKey) external",
    "function getPublicKey(address user) external view returns (bytes)",
    "function hasPublicKey(address user) external view returns (bool)"
];

const ESCROW_ABI = [
    "function deposit(address stealthAddress, bytes calldata senderPubKey) external payable",
    "function claim(address stealthAddress, address recipient, bytes memory signature) external",
    "function deposits(address) external view returns (uint256)",
    "event EtherDeposited(address indexed stealthAddress, uint256 amount, bytes senderPubKey)"
];

const CARRIER_ADDRESS = "0x1880FC712f90a4F3CfdA1401c0e254B4a164ED17";
const ESCROW_ADDRESS = "0x523B977C37d7F37Ea1Be4e4162F807C4EF888eEd";


let provider: ethers.JsonRpcProvider;
let signer: ethers.Wallet;
let carrierContract: ethers.Contract;
let escrowContract: ethers.Contract;

/** setup wallet and contracts (persistent) */
async function setupContracts(): Promise<void> {
    const { privateKey, rpcUrl, password } = await inquirer.prompt([
        { type: "password", name: "password", message: "🔑 Enter encryption password:" },
        { type: "password", name: "privateKey", message: "🔐 Enter your private key:" },
        { type: "input", name: "rpcUrl", message: "🌐 Enter your RPC URL:" }
    ]);

    provider = new ethers.JsonRpcProvider(rpcUrl);
    signer = new ethers.Wallet(privateKey, provider);
    carrierContract = new ethers.Contract(CARRIER_ADDRESS, CARRIER_ABI, signer);
    escrowContract = new ethers.Contract(ESCROW_ADDRESS, ESCROW_ABI, signer);

    encryptConfig({ privateKey, rpcUrl }, password);
}

/** rnsure setup is loaded before running commands */
async function ensureSetup(): Promise<void> {
    const { password } = await inquirer.prompt([
        { type: "password", name: "password", message: "🔑 Enter encryption password:" }
    ]);
    const config = decryptConfig(password);
    if (!config) {
        console.error(chalk.red("❌ Error: Setup is required! Run `bun cli.ts setup`"));
        process.exit(1);
    }
    provider = new ethers.JsonRpcProvider(config.rpcUrl);
    signer = new ethers.Wallet(config.privateKey, provider);
    carrierContract = new ethers.Contract(CARRIER_ADDRESS, CARRIER_ABI, signer);
    escrowContract = new ethers.Contract(ESCROW_ADDRESS, ESCROW_ABI, signer);
}

/** register Public Key */
async function registerPublicKey(): Promise<void> {
    await ensureSetup();

    try {
        console.log(chalk.blue("🔹 Generating public key..."));
        const privateKeyBytes = ethers.getBytes(signer.privateKey);
        const publicKey = secp.secp256k1.getPublicKey(privateKeyBytes, true);

        console.log("\nDebug Info (Register):");
        console.log("Wallet Address:", await signer.getAddress());
        console.log("Private Key:", signer.privateKey);
        console.log("Public Key (bytes):", ethers.hexlify(publicKey));
        console.log("Public Key Length:", publicKey.length);

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

// generate Stealth Address
async function generateStealthAddress(recipientAddress: string): Promise<string> {
    await ensureSetup();

    console.log(chalk.blue(`🔍 Checking if ${recipientAddress} has a registered public key...`));
    const hasPublicKey = await carrierContract.hasPublicKey(recipientAddress);
    if (!hasPublicKey) {
        throw new Error("❌ Recipient has NOT registered a public key.");
    }

    const recipientPublicKey = await carrierContract.getPublicKey(recipientAddress);
    console.log(chalk.yellow("📡 Recipient Public Key:"), recipientPublicKey);

    // generate an Ephemeral Key Pair
    console.log(chalk.blue("🔑 Generating one-time ephemeral key..."));
    const ephemeralPrivateKey = secp.secp256k1.utils.randomPrivateKey();
    const ephemeralPublicKey = secp.secp256k1.getPublicKey(ephemeralPrivateKey, true);
    console.log(chalk.yellow("📢 Ephemeral Public Key (Sent to recipient):"), ethers.hexlify(ephemeralPublicKey));

    // compute Shared Secret
    const sharedSecret = secp.secp256k1.getSharedSecret(
        ephemeralPrivateKey,
        ethers.getBytes(recipientPublicKey)
    );

    // compute Stealth Address
    console.log(chalk.blue("🔁 Hashing Shared Secret..."));
    const hashedSecret = ethers.keccak256(sharedSecret);
    const scalar = BigInt("0x" + hashedSecret.slice(2)) % secp.secp256k1.CURVE.n;

    const recipientPubKeyPoint = secp.secp256k1.ProjectivePoint.fromHex(
        ethers.getBytes(recipientPublicKey)
    );

    const stealthPubKey = recipientPubKeyPoint
        .add(secp.secp256k1.ProjectivePoint.BASE.multiply(scalar))
        .toRawBytes(true);

    const stealthAddress = ethers.computeAddress("0x" + Buffer.from(stealthPubKey).toString("hex"));
    console.log(chalk.green("✅ Stealth Address Generated:"), chalk.yellow(stealthAddress));

    return stealthAddress;
}

async function sendFunds(recipientAddress: string, amount: string): Promise<void> {
    await ensureSetup();

    console.log(chalk.blue("\n🔹 Starting fund transfer process..."));
    console.log("\nDebug Info (Send):");
    console.log("Sender Address:", await signer.getAddress());
    console.log("Recipient Address:", recipientAddress);
    console.log("Amount:", amount, "ETH");

    // Get recipient's public key
    const hasPublicKey = await carrierContract.hasPublicKey(recipientAddress);
    if (!hasPublicKey) {
        throw new Error("❌ Recipient has NOT registered a public key.");
    }

    const recipientPublicKey = await carrierContract.getPublicKey(recipientAddress);
    console.log("\nRecipient Public Key Info:");
    console.log("Public Key:", recipientPublicKey);
    console.log("Length:", ethers.getBytes(recipientPublicKey).length);

    // Generate ephemeral key pair
    console.log(chalk.blue("\n🔑 Generating one-time ephemeral key..."));
    const ephemeralPrivateKey = secp.secp256k1.utils.randomPrivateKey();
    const ephemeralPublicKey = secp.secp256k1.getPublicKey(ephemeralPrivateKey, true);

    console.log("\nEphemeral Key Info:");
    console.log("Private Key:", ethers.hexlify(ephemeralPrivateKey));
    console.log("Public Key:", ethers.hexlify(ephemeralPublicKey));
    console.log("Public Key Length:", ephemeralPublicKey.length);

    // compute shared secret and stealth address
    const sharedSecret = secp.secp256k1.getSharedSecret(
        ephemeralPrivateKey,
        ethers.getBytes(recipientPublicKey)
    );

    console.log("\nShared Secret Info:");
    console.log("Shared Secret:", ethers.hexlify(sharedSecret));

    const hashedSecret = ethers.keccak256(sharedSecret);
    const scalar = BigInt("0x" + hashedSecret.slice(2)) % secp.secp256k1.CURVE.n;

    console.log("\nScalar Computation:");
    console.log("Hashed Secret:", hashedSecret);
    console.log("Scalar:", scalar.toString(16));

    const recipientPubKeyPoint = secp.secp256k1.ProjectivePoint.fromHex(
        ethers.getBytes(recipientPublicKey)
    );

    const stealthPubKey = recipientPubKeyPoint
        .add(secp.secp256k1.ProjectivePoint.BASE.multiply(scalar))
        .toRawBytes(true);

    const stealthAddress = ethers.computeAddress("0x" + Buffer.from(stealthPubKey).toString("hex"));

    console.log("\nStealth Address Info:");
    console.log("Stealth Public Key:", ethers.hexlify(stealthPubKey));
    console.log("Stealth Address:", stealthAddress);

    console.log(chalk.blue("\n📡 Sending transaction..."));
    const tx = await escrowContract.deposit(
        stealthAddress,
        ephemeralPublicKey,
        { value: ethers.parseEther(amount) }
    );

    console.log(chalk.yellow("\n⌛ Transaction pending..."), tx.hash);
    const receipt = await tx.wait();

    console.log("\nTransaction Info:");
    console.log("Transaction Hash:", receipt.hash);
    console.log("Block Number:", receipt.blockNumber);
    console.log("Gas Used:", receipt.gasUsed.toString());

    console.log(chalk.green("\n✅ Transfer Summary:"));
    console.log("Amount:", amount, "ETH");
    console.log("Stealth Address:", stealthAddress);
    console.log("Ephemeral Public Key:", ethers.hexlify(ephemeralPublicKey));
}

async function scanDeposits(): Promise<void> {
    await ensureSetup();

    console.log(chalk.blue("🔎 Scanning for deposits..."));
    const currentBlock = await provider.getBlockNumber();
    const fromBlock = Math.max(0, currentBlock - 10000);

    const filter = escrowContract.filters.EtherDeposited();
    const events = await escrowContract.queryFilter(filter, fromBlock, currentBlock);

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
                name: `ETH: ${ethers.formatEther(event.args.amount)} at ${event.args.stealthAddress}`,
                value: i
            }))
        }
    ]);

    const deposit = events[depositIndex].args;
    await claimFunds(deposit.stealthAddress, deposit.senderPubKey);
}


// Claim Funds
async function claimFunds(stealthAddress: string, ephemeralPubKey: string): Promise<void> {
    await ensureSetup();

    console.log(chalk.blue("\n🔑 Starting claim process..."));
    console.log("\nDebug Info (Claim):");
    console.log("Stealth Address:", stealthAddress);
    console.log("Ephemeral Public Key:", ephemeralPubKey);

    // Get recipient's private key (our private key)
    const recipientPrivateKey = signer.privateKey;

    // Compute shared secret using recipient private key and ephemeral public key
    const sharedSecret = secp.secp256k1.getSharedSecret(
        ethers.getBytes(recipientPrivateKey),
        ethers.getBytes(ephemeralPubKey)
    );

    console.log("\nShared Secret Info:");
    console.log("Shared Secret:", ethers.hexlify(sharedSecret));

    // Compute stealth private key
    const hashedSecret = ethers.keccak256(sharedSecret);
    const scalar = BigInt('0x' + hashedSecret.slice(2)) % secp.secp256k1.CURVE.n;

    // Make sure private key has 0x prefix for BigInt conversion
    const privateKeyHex = recipientPrivateKey.startsWith('0x')
        ? recipientPrivateKey
        : '0x' + recipientPrivateKey;
    const privateKeyBigInt = BigInt(privateKeyHex);

    // Calculate stealth private key
    const stealthPrivateKey = (privateKeyBigInt + scalar) % secp.secp256k1.CURVE.n;
    const stealthPrivateKeyHex = '0x' + stealthPrivateKey.toString(16).padStart(64, '0');

    // Create stealth wallet (only for signing, not for sending tx)
    const stealthWallet = new ethers.Wallet(stealthPrivateKeyHex);
    const derivedStealthAddress = await stealthWallet.getAddress();

    console.log("\nStealth Wallet Info:");
    console.log("Derived Address:", derivedStealthAddress);
    console.log("Expected Address:", stealthAddress);
    console.log("Addresses Match:", derivedStealthAddress.toLowerCase() === stealthAddress.toLowerCase());

    // Ask for relayer private key
    const { relayerKey } = await inquirer.prompt([
        {
            type: "password",
            name: "relayerKey",
            message: "🔑 Enter relayer private key (different account to submit tx):"
        }
    ]);

    // Create relayer wallet and contract
    const relayer = new ethers.Wallet(relayerKey, provider);
    const relayerContract = new ethers.Contract(ESCROW_ADDRESS, ESCROW_ABI, relayer);

    // Get the address where funds will be sent
    const recipient = await signer.getAddress();

    // Create and sign the message with stealth wallet
    const messageHash = ethers.keccak256(
        ethers.solidityPacked(
            ["address", "address"],
            [await relayer.getAddress(), stealthAddress]
        )
    );
    const signature = await stealthWallet.signMessage(ethers.getBytes(messageHash));


    console.log("\nClaim Info:");
    console.log("Recipient:", recipient);
    console.log("Message Hash:", messageHash);
    console.log("Signature:", signature);
    console.log("Stealth Address:", stealthAddress);
    console.log("\nRelayer Info:");
    console.log("Relayer Address:", await relayer.getAddress());

    try {
        console.log(chalk.blue("\n📡 Submitting claim transaction via relayer..."));
        const tx = await relayerContract.claim(stealthAddress, relayer.address, signature);
        console.log(chalk.yellow("⌛ Transaction pending..."), tx.hash);
        const receipt = await tx.wait();

        console.log("\nTransaction Info:");
        console.log("Transaction Hash:", receipt.hash);
        console.log("Block Number:", receipt.blockNumber);
        console.log("Gas Used:", receipt.gasUsed.toString());

        console.log(chalk.green("\n✅ Funds claimed successfully!"));
    } catch (error) {
        console.error(chalk.red("\n❌ Failed to claim funds:"), error);
        if (error instanceof Error) {
            console.error(chalk.red("Error details:"), error.message);
        }
    }
}

/** Bun CLI Commands */
program.version("1.0.0").description("Stealth Payment System CLI");

program
    .command("setup")
    .description("Setup wallet and contracts securely")
    .action(setupContracts);

program
    .command("register")
    .description("Register public key")
    .action(registerPublicKey);

program
    .command("generate")
    .description("Generate stealth address")
    .requiredOption("-r, --recipient <address>", "Recipient address")
    .action(async (options: { recipient: string }) => {
        await generateStealthAddress(options.recipient);
    });

program
    .command("send")
    .description("Send funds to recipient using stealth address")
    .requiredOption("-r, --recipient <address>", "Recipient's address")
    .requiredOption("-a, --amount <amount>", "Amount in ETH")
    .action(async (options: { recipient: string; amount: string }) => {
        await sendFunds(options.recipient, options.amount);
    });

program
    .command("scan")
    .description("Scan for deposits that can be claimed")
    .action(scanDeposits);

program.parse(process.argv);
if (!process.argv.slice(2).length) {
    program.outputHelp();
}