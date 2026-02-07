// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypes} from "../libraries/AxiomTypes.sol";

/**
 * @title AxiomStorage
 * @author Axiom Protocol Team
 * @notice Diamond storage pattern for upgradeable contracts
 * @dev All state variables are stored in a single struct at a fixed storage slot
 */
library AxiomStorage {
    // ============ Storage Position ============
    
    /// @dev Unique storage slot for Axiom Protocol
    bytes32 constant AXIOM_STORAGE_POSITION = keccak256("axiom.protocol.storage.v1");

    // ============ Storage Struct ============

    /**
     * @notice Main storage structure containing all protocol state
     * @dev Using Diamond storage pattern for upgradeability
     */
    struct Storage {
        // ============ Registry State ============
        
        /// @notice Maps recordId to AxiomRecord
        mapping(bytes32 => AxiomTypes.AxiomRecord) records;
        
        /// @notice Maps user address to their registered record IDs
        mapping(address => bytes32[]) userRecords;
        
        /// @notice Maps content hash + issuer to recordId (for duplicate checking)
        mapping(bytes32 => bool) hashExists;
        
        /// @notice Total number of registered records
        uint256 totalRecords;

        // ============ Identity State ============
        
        /// @notice Maps address to identity information
        mapping(address => AxiomTypes.IdentityInfo) identities;
        
        /// @notice Maps name hash to address (reverse lookup)
        mapping(bytes32 => address) nameToAddress;

        // ============ Access Control State ============
        
        /// @notice Maps address to banned status
        mapping(address => bool) bannedAddresses;
        
        /// @notice Maps address to last action timestamp (for rate limiting)
        mapping(address => uint256) lastActionTime;
        
        /// @notice Maps address to action count in current window
        mapping(address => uint256) actionCount;
        
        /// @notice Rate limit window in seconds
        uint256 rateLimitWindow;
        
        /// @notice Max actions per window for regular users
        uint256 maxActionsPerWindow;

        // ============ Treasury State ============
        
        /// @notice Base fee for content registration (in wei)
        uint256 baseFee;
        
        /// @notice Custom rates for enterprise users
        mapping(address => uint256) enterpriseRates;
        
        /// @notice Whether an address has enterprise status
        mapping(address => bool) isEnterprise;
        
        /// @notice Treasury wallet address for fee collection
        address treasuryWallet;
        
        /// @notice Total fees collected
        uint256 totalFeesCollected;

        // ============ Configuration ============
        
        /// @notice Maximum batch size for batch operations
        uint256 maxBatchSize;
        
        /// @notice Protocol version
        uint256 protocolVersion;
        
        /// @notice Whether the protocol is paused
        /// @notice Whether the protocol is paused
        bool paused;
        
        /// @notice Address of the AxiomModuleHub (v2 upgrade)
        address moduleHub;
    }

    // ============ Storage Access ============

    /**
     * @notice Get the storage struct at the fixed position
     * @return s Storage struct reference
     */
    function getStorage() internal pure returns (Storage storage s) {
        bytes32 position = AXIOM_STORAGE_POSITION;
        assembly {
            s.slot := position
        }
    }

    // ============ Helper Functions ============

    /**
     * @notice Generate a unique record ID from content hash and issuer
     * @dev Using issuer address prevents front-running attacks
     * @param _contentHash The hash of the content
     * @param _issuer The issuer's address
     * @return recordId Unique identifier for the record
     */
    function generateRecordId(
        bytes32 _contentHash,
        address _issuer
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_contentHash, _issuer));
    }

    /**
     * @notice Check if a record exists
     * @param _recordId The record ID to check
     * @return exists Whether the record exists
     */
    function recordExists(bytes32 _recordId) internal view returns (bool) {
        Storage storage s = getStorage();
        return s.records[_recordId].timestamp != 0;
    }
}
