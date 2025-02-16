pragma circom 2.0.0;
include "./circomlib/circuits/poseidon.circom";

template CommitmentProof() {
    // Private Input
    signal input secret;

    // Public Input
    signal input commitment;
    
    // Public Outputs
    signal output computed_commitment;
    signal output computed_nullifier;

    // Compute commitment from secret
    component poseidon_commitment = Poseidon(1);
    poseidon_commitment.inputs[0] <== secret;
    computed_commitment <== poseidon_commitment.out;

    // Verify provided commitment matches computed one
    commitment === computed_commitment;

    // Compute nullifier deterministically from commitment and secret
    component poseidon_nullifier = Poseidon(2);
    poseidon_nullifier.inputs[0] <== computed_commitment;
    poseidon_nullifier.inputs[1] <== secret;
    computed_nullifier <== poseidon_nullifier.out;
}

// ✅ Declare main component
component main = CommitmentProof();