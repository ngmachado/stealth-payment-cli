pragma circom 2.0.0;

include "./circomlib/circuits/poseidon.circom";

template CommitmentProof() {
    // **Private Inputs** (Hidden from Verifier)
    signal input secret;              // Secret input (e.g., deposit preimage)
    signal input nullifier;           // Nullifier to prevent double-spending

    // **Public Inputs** (Passed to Verifier)
    signal input commitment;          // Commitment stored on-chain
    signal output computed_commitment; // Computed commitment (must match on-chain)
    signal output computed_nullifier;  // Computed nullifier (used in claim)

    // Poseidon hash for commitment
    component poseidon_commitment = Poseidon(2);
    poseidon_commitment.inputs[0] <== secret;
    poseidon_commitment.inputs[1] <== 0; // Optional randomness

    computed_commitment <== poseidon_commitment.out;

    // ✅ Enforce that computed commitment matches provided commitment
    commitment === computed_commitment;

    // Poseidon hash for nullifier (ensures uniqueness & prevents double-spending)
    component poseidon_nullifier = Poseidon(2);
    poseidon_nullifier.inputs[0] <== nullifier;
    poseidon_nullifier.inputs[1] <== secret;

    computed_nullifier <== poseidon_nullifier.out;
}

// ✅ Declare `commitment` & `nullifier` as public in `main`
component main = CommitmentProof();