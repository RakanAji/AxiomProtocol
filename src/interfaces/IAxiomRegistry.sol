// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypes} from "../libraries/AxiomTypes.sol";

/**
 * @title IAxiomRegistry
 * @notice Interface for the Axiom Registry contract
 */
interface IAxiomRegistry {
    /**
     * @notice Register new content hash
     * @param _contentHash SHA-256 hash of the content
     * @param _metadataURI IPFS/Arweave link to metadata JSON
     * @return recordId Unique identifier for the registered record
     */
    function register(
        bytes32 _contentHash,
        string calldata _metadataURI
    ) external payable returns (bytes32 recordId);

    /**
     * @notice Register multiple content hashes in a single transaction
     * @param _contentHashes Array of content hashes
     * @param _metadataURIs Array of metadata URIs
     * @return recordIds Array of generated record IDs
     */
    function batchRegister(
        bytes32[] calldata _contentHashes,
        string[] calldata _metadataURIs
    ) external payable returns (bytes32[] memory recordIds);

    /**
     * @notice Revoke a previously registered content
     * @param _recordId The record ID to revoke
     * @param _reason Reason for revocation
     */
    function revoke(bytes32 _recordId, string calldata _reason) external;

    /**
     * @notice Verify content authenticity
     * @param _contentHash The content hash to verify
     * @param _claimedIssuer The claimed issuer address
     * @return isValid Whether the content is valid
     * @return record The full record data
     */
    function verify(
        bytes32 _contentHash,
        address _claimedIssuer
    ) external view returns (bool isValid, AxiomTypes.AxiomRecord memory record);

    /**
     * @notice Get record by ID
     * @param _recordId The record ID
     * @return record The record data
     */
    function getRecord(bytes32 _recordId) 
        external view returns (AxiomTypes.AxiomRecord memory record);

    /**
     * @notice Get all records by issuer
     * @param _issuer The issuer address
     * @return recordIds Array of record IDs
     */
    function getRecordsByIssuer(address _issuer) 
        external view returns (bytes32[] memory recordIds);

    /**
     * @notice Get total number of records
     * @return count Total record count
     */
    function getTotalRecords() external view returns (uint256 count);
}
