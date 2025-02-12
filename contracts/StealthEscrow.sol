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
