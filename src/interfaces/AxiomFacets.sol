// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypes} from "../libraries/AxiomTypes.sol";

/**
 * @title AxiomFacets
 * @notice Helper interface aggregating all facet functions for testing Diamond proxy
 * @dev This interface should only be used in tests to make casting easier.
 *      In production, the Diamond proxy routes calls to the appropriate facets.
 */
interface AxiomFacets {
    // ============ AxiomRegistry Functions ============
    function register(bytes32 _contentHash, string calldata _metadataURI) external payable returns (bytes32);
    function batchRegister(bytes32[] calldata _contentHashes, string[] calldata _metadataURIs) external payable returns (bytes32[] memory);
    function revoke(bytes32 _recordId, string calldata _reason) external;
    function verify(bytes32 _contentHash, address _claimedIssuer) external view returns (bool, AxiomTypes.AxiomRecord memory);
    function getRecord(bytes32 _recordId) external view returns (AxiomTypes.AxiomRecord memory);
    function getRecordsByIssuer(address _issuer) external view returns (bytes32[] memory);
    function getTotalRecords() external view returns (uint256);
    
    // ============ AxiomTreasury Functions ============
    function setBaseFee(uint256 _fee) external;
    function setEnterpriseRate(address _user, uint256 _rate) external;
    function grantEnterpriseStatus(address _user) external;
    function revokeEnterpriseStatus(address _user) external;
    function withdraw(address _to, uint256 _amount) external;
    function setTreasuryWallet(address _wallet) external;
    function getFee(address _user) external view returns (uint256);
    function getBaseFee() external view returns (uint256);
    function getTotalFeesCollected() external view returns (uint256);
    function isEnterpriseUser(address _user) external view returns (bool);
    
    // ============ AxiomIdentity Functions ============
    function registerIdentity(string calldata _name, string calldata _proofURI) external;
    function updateIdentity(string calldata _name, string calldata _proofURI) external;
    function verifyIdentity(address _user) external;
    function revokeVerification(address _user) external;
    function resolveIdentity(address _user) external view returns (AxiomTypes.IdentityInfo memory);
    function resolveByName(string calldata _name) external view returns (address);
    function isIdentityVerified(address _user) external view returns (bool);
    
    // ============ AxiomAccess Functions ============
    function banAddress(address _user, string calldata _reason) external;
    function unbanAddress(address _user) external;
    function isBanned(address _user) external view returns (bool);
    function disputeContent(bytes32 _recordId, string calldata _reason) external;
    function setRateLimit(uint256 _window, uint256 _maxActions) external;
    function setMaxBatchSize(uint256 _size) external;
}

