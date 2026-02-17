// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IZKVerifier
 * @author Axiom Protocol Team
 * @notice Interface for Zero-Knowledge Proof Verifier (Groth16-compatible)
 * @dev Defines the standard Groth16 verification signature used by both
 *      the production Groth16Verifier and the test MockVerifier.
 *
 *      Proof structure (Groth16):
 *        - pA ∈ G1: [x, y] — first proof element
 *        - pB ∈ G2: [[x_im, x_re], [y_im, y_re]] — second proof element
 *        - pC ∈ G1: [x, y] — third proof element
 *        - pubSignals: array of public circuit inputs
 *
 *      Implementations:
 *        - Groth16Verifier (production): Full BN254 pairing verification
 *        - MockVerifier (testing): Always returns true
 */
interface IZKVerifier {
    /**
     * @notice Verify a Groth16 ZK-SNARK proof
     * @param _pA Proof point A ∈ G1: [x, y]
     * @param _pB Proof point B ∈ G2: [[x_im, x_re], [y_im, y_re]]
     * @param _pC Proof point C ∈ G1: [x, y]
     * @param _pubSignals Public inputs to the circuit
     * @return valid True if proof is valid
     */
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata _pubSignals
    ) external view returns (bool valid);
}
