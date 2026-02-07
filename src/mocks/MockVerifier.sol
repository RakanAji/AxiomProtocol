// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZKVerifier} from "../interfaces/IZKVerifier.sol";

/**
 * @title MockVerifier
 * @author Axiom Protocol Team
 * @notice Mock ZK Verifier for testing purposes
 * @dev Always returns true used for devnet/testnet
 */
contract MockVerifier is IZKVerifier {
    function verifyProof(
        bytes calldata /*_proof*/,
        uint256[] calldata /*_publicInputs*/
    ) external pure override returns (bool) {
        return true;
    }
}
