// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Carrier
 * @notice A registry for users to publish their public keys for stealth addresses
 */
contract Carrier {
    /// @notice Structure to store public key data
    struct PublicKeyEntry {
        bytes publicKey; // Compressed public key (ECDSA)
        uint64 updatedAt;
        uint64 version;
    }

    /// @notice Mapping from user address to their public key entry
    mapping(address => PublicKeyEntry) private publicKeys;

    // Events
    event PublicKeyPublished(
        address indexed user,
        bytes publicKey,
        uint64 indexed version,
        uint64 timestamp
    );
    event PublicKeyRevoked(
        address indexed user,
        bytes publicKey,
        uint64 timestamp
    );

    // Errors
    error InvalidPublicKeyLength();
    error InvalidPublicKeyFormat();
    error NoPublicKeyToRevoke();

    /**
     * @notice Publish or update your public key
     * @param newPublicKey The new public key in compressed format
     */
    function publishPublicKey(bytes calldata newPublicKey) external {
        // Check public key length (33 bytes for compressed)
        if (newPublicKey.length != 33) revert InvalidPublicKeyLength();

        // Check public key format (must start with 02 or 03)
        if (newPublicKey[0] != 0x02 && newPublicKey[0] != 0x03) {
            revert InvalidPublicKeyFormat();
        }

        // Load the existing public key entry to avoid multiple SLOADs
        PublicKeyEntry memory currentEntry = publicKeys[msg.sender];

        // If the user has a public key, check if the new one is different
        if (currentEntry.updatedAt != 0) {
            if (keccak256(currentEntry.publicKey) != keccak256(newPublicKey)) {
                _revokePublicKey(msg.sender);
            }
        }

        // Update public key entry
        publicKeys[msg.sender] = PublicKeyEntry({
            publicKey: newPublicKey,
            updatedAt: uint64(block.timestamp),
            version: currentEntry.version + 1
        });

        emit PublicKeyPublished(
            msg.sender,
            newPublicKey,
            currentEntry.version + 1,
            uint64(block.timestamp)
        );
    }

    /**
     * @notice Retrieve a public key by Ethereum address
     * @param user The Ethereum address to look up
     */
    function getPublicKey(address user) external view returns (bytes memory) {
        return publicKeys[user].publicKey;
    }

    /**
     * @notice Revoke your public key
     */
    function revokePublicKey() public {
        _revokePublicKey(msg.sender);
    }

    /**
     * @notice Check if an address has a registered public key
     */
    function hasPublicKey(address user) external view returns (bool) {
        return publicKeys[user].updatedAt != 0;
    }

    function _revokePublicKey(address user) internal {
        PublicKeyEntry memory currentEntry = publicKeys[user];
        if (currentEntry.updatedAt == 0) revert NoPublicKeyToRevoke();

        bytes memory revokedKey = currentEntry.publicKey;
        delete publicKeys[user];
        emit PublicKeyRevoked(user, revokedKey, uint64(block.timestamp));
    }
}
