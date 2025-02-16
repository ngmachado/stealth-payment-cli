// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract StealthEscrow {
    // Mapping from stealth address to deposited amount
    mapping(address => uint256) public deposits;

    event EtherDeposited(
        address indexed stealthAddress,
        uint256 amount,
        bytes senderPubKey
    );
    event EtherClaimed(
        address indexed stealthAddress,
        address indexed recipient,
        uint256 amount
    );

    error NoDeposit();
    error InvalidSignature();

    /**
     * @notice Deposit ETH for a stealth address
     * @param stealthAddress The stealth address that can claim the funds
     * @param senderPubKey The public key of the sender
     */
    function deposit(
        address stealthAddress,
        bytes calldata senderPubKey
    ) external payable {
        require(msg.value > 0, "Must deposit some ETH");
        require(senderPubKey.length == 33, "Invalid public key length");
        deposits[stealthAddress] += msg.value;
        emit EtherDeposited(stealthAddress, msg.value, senderPubKey);
    }

    /**
     * @notice Claim ETH using a signature from the stealth address
     * @param stealthAddress The stealth address that owns the deposit
     * @param recipient The address to receive the funds
     * @param signature The signature proving ownership of the stealth address
     */
    function claim(
        address stealthAddress,
        address recipient,
        bytes memory signature
    ) external {
        uint256 amount = deposits[stealthAddress];
        if (amount == 0) revert NoDeposit();

        // Verify the signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(recipient, stealthAddress))
            )
        );

        address signer = recoverSigner(messageHash, signature);
        if (signer != stealthAddress) revert InvalidSignature();

        // Transfer the funds
        deposits[stealthAddress] = 0;
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit EtherClaimed(stealthAddress, recipient, amount);
    }

    function recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;
        require(v == 27 || v == 28, "Invalid signature 'v' value");

        return ecrecover(messageHash, v, r, s);
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Verifier.sol";

contract StealthEscrow {
    Groth16Verifier public verifier;

    // Core state variables
    mapping(bytes32 => uint256) public commitments;
    mapping(bytes32 => bool) public nullifiersUsed;

    // Events
    event EtherDeposited(
        uint256 commitment,
        uint256 amount,
        bytes ephemeralPubKey
    );
    event EtherClaimed(address indexed recipient, uint256 amount);

    // Custom errors
    error InvalidVerifier();
    error NoEthSent();
    error CommitmentExists();
    error CommitmentNotFound();
    error NullifierUsed();
    error InvalidProof();
    error TransferFailed();

    /**
     * @notice Constructor to set the Verifier contract address
     * @param _verifier The deployed Verifier contract address
     */
    constructor(address _verifier) {
        require(_verifier != address(0), InvalidVerifier);
        verifier = Groth16Verifier(_verifier);
    }

    /**
     * @notice Deposit ETH into the escrow using a commitment
     * @param commitment The zk-SNARK commitment hash
     * @param ephemeralPubKey The sender's ephemeral public key
     */
    function deposit(
        uint256 commitment,
        bytes calldata ephemeralPubKey
    ) external payable {
        require(msg.value > 0, NoEthSent());
        bytes32 commitmentKey = bytes32(commitment);
        require(commitments[commitmentKey] == 0, CommitmentExists());

        commitments[commitmentKey] = msg.value;
        emit EtherDeposited(commitment, msg.value, ephemeralPubKey);
    }

    /**
     * @notice Claim ETH using a zk-SNARK proof
     * @param a zk-SNARK proof parameter
     * @param b zk-SNARK proof parameter
     * @param c zk-SNARK proof parameter
     * @param publicSignals Public inputs: [nullifier, commitment]
     * @param recipient Address to receive the funds
     */
    function claim(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[2] calldata publicSignals,
        address recipient
    ) external {
        bytes32 commitment = bytes32(publicSignals[0]);
        bytes32 nullifier = bytes32(publicSignals[1]);

        require(commitments[commitment] > 0, CommitmentNotFound());
        require(!nullifiersUsed[nullifier], NullifierUsed);
        require(verifier.verifyProof(a, b, c, publicSignals), InvalidProof);

        uint256 amount = commitments[commitment];
        commitments[commitment] = 0;
        nullifiersUsed[nullifier] = true;

        (bool success, ) = recipient.call{value: amount}("");
        require(success, TransferFailed);

        emit EtherClaimed(recipient, amount);
    }

    // Add view function to check stored commitment
    function getStoredAmount(uint256 commitment) public view returns (uint256) {
        bytes32 key = bytes32(commitment);
        return commitments[key];
    }

    // Make consistent with how we check in claim()
    function hasCommitment(uint256 commitment) public view returns (bool) {
        return commitments[bytes32(commitment)] > 0;
    }
}
