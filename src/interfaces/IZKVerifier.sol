// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IZKVerifier
 * @author Axiom Protocol Team
 * @notice Interface for Zero-Knowledge Proof Verifier
 */
interface IZKVerifier {
    /**
     * @notice Verify a ZK-SNARK proof
     * @param _proof Encoded proof data (e.g., Groth16 a, b, c)
     * @param _publicInputs Public inputs to the circuit (e.g., commitment hash, nullifier)
     * @return valid True if proof is valid
     */
    function verifyProof(
        bytes calldata _proof,
        uint256[] calldata _publicInputs
    ) external view returns (bool valid);
}
