// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZKVerifier} from "../../src/interfaces/IZKVerifier.sol";

/**
 * @title MockVerifier
 * @author Axiom Protocol Team
 * @notice Test-only mock that always returns true for any proof
 * @dev This contract implements the IZKVerifier interface but skips all
 *      cryptographic verification. It is used in Foundry tests via
 *      dependency injection:
 *
 *      1. Deploy MockVerifier
 *      2. Call diamond.setZKVerifier(address(mockVerifier))
 *      3. All privateRegister / verifyOwnership calls succeed with any proof
 *
 *      NEVER deploy this contract to mainnet or testnet. In production,
 *      use the real Groth16Verifier with proper verification key constants.
 */
contract MockVerifier is IZKVerifier {
    /// @notice Always returns true regardless of proof inputs
    /// @dev Satisfies the IZKVerifier interface for testing
    function verifyProof(
        uint256[2] calldata, /* _pA */
        uint256[2][2] calldata, /* _pB */
        uint256[2] calldata, /* _pC */
        uint256[] calldata /* _pubSignals */
    ) external pure override returns (bool) {
        return true;
    }
}
