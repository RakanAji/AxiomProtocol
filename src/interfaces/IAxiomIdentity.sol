// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypes} from "../libraries/AxiomTypes.sol";

/**
 * @title IAxiomIdentity
 * @notice Interface for identity management
 */
interface IAxiomIdentity {
    /**
     * @notice Register an identity name
     * @param _name Display name for the identity
     * @param _proofURI Link to identity proof document
     */
    function registerIdentity(
        string calldata _name,
        string calldata _proofURI
    ) external;

    /**
     * @notice Update existing identity
     * @param _name New display name
     * @param _proofURI New proof URI
     */
    function updateIdentity(
        string calldata _name,
        string calldata _proofURI
    ) external;

    /**
     * @notice Verify an identity (Operator only)
     * @param _user Address to verify
     */
    function verifyIdentity(address _user) external;

    /**
     * @notice Revoke verification (Operator only)
     * @param _user Address to unverify
     */
    function revokeVerification(address _user) external;

    /**
     * @notice Resolve address to identity info
     * @param _user Address to resolve
     * @return info Identity information
     */
    function resolveIdentity(address _user) 
        external view returns (AxiomTypes.IdentityInfo memory info);

    /**
     * @notice Check if identity is verified
     * @param _user Address to check
     * @return isVerified Whether identity is verified
     */
    function isIdentityVerified(address _user) external view returns (bool isVerified);

    /**
     * @notice Resolve name to address
     * @param _name Name to resolve
     * @return user Address of the identity
     */
    function resolveByName(string calldata _name) external view returns (address user);
}
