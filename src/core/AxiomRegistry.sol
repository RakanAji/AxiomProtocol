// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AxiomTypes} from "../libraries/AxiomTypes.sol";
import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {IAxiomRegistry} from "../interfaces/IAxiomRegistry.sol";

/**
 * @title AxiomRegistry
 * @author Axiom Protocol Team
 * @notice Core registry contract for content hash registration and verification
 * @dev Implements anti-front-running via sender-bound record IDs
 */
contract AxiomRegistry is 
    Initializable, 
    ReentrancyGuard,
    IAxiomRegistry 
{
    using AxiomStorage for AxiomStorage.Storage;

    // ============ Modifiers ============

    /**
     * @dev Ensures caller is not banned
     */
    modifier notBanned() {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        if (s.bannedAddresses[msg.sender]) {
            revert AxiomTypes.AddressBanned(msg.sender);
        }
        _;
    }

    /**
     * @dev Ensures protocol is not paused
     */
    modifier whenNotPaused() {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        require(!s.paused, "Protocol is paused");
        _;
    }

    /**
     * @dev Implements rate limiting for non-enterprise users
     */
    modifier rateLimit() {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Enterprise users bypass rate limit
        if (!s.isEnterprise[msg.sender]) {
            uint256 currentWindow = block.timestamp / s.rateLimitWindow;
            uint256 lastWindow = s.lastActionTime[msg.sender] / s.rateLimitWindow;
            
            if (currentWindow == lastWindow) {
                if (s.actionCount[msg.sender] >= s.maxActionsPerWindow) {
                    revert AxiomTypes.RateLimitExceeded(msg.sender);
                }
                s.actionCount[msg.sender]++;
            } else {
                s.actionCount[msg.sender] = 1;
            }
            s.lastActionTime[msg.sender] = block.timestamp;
        }
        _;
    }

    // ============ External Functions ============

    /**
     * @inheritdoc IAxiomRegistry
     */
    function register(
        bytes32 _contentHash,
        string calldata _metadataURI
    ) external payable override nonReentrant notBanned whenNotPaused rateLimit returns (bytes32 recordId) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Generate unique record ID (includes sender to prevent front-running)
        recordId = AxiomStorage.generateRecordId(_contentHash, msg.sender);
        
        // Check for duplicates
        if (AxiomStorage.recordExists(recordId)) {
            revert AxiomTypes.ContentAlreadyExists(recordId);
        }
        
        // Check fee
        uint256 requiredFee = _getFee(msg.sender);
        if (msg.value < requiredFee) {
            revert AxiomTypes.InsufficientFee(msg.value, requiredFee);
        }
        
        // Create and store record
        s.records[recordId] = AxiomTypes.AxiomRecord({
            issuer: msg.sender,
            timestamp: uint40(block.timestamp),
            status: AxiomTypes.ContentStatus.ACTIVE,
            algorithm: AxiomTypes.HashAlgorithm.SHA256,
            contentHash: _contentHash,
            metadataURI: _metadataURI
        });
        
        // Update tracking
        s.userRecords[msg.sender].push(recordId);
        s.hashExists[recordId] = true;
        s.totalRecords++;
        s.totalFeesCollected += msg.value;
        
        // Emit events
        emit AxiomTypes.ContentRegistered(
            recordId,
            msg.sender,
            _contentHash,
            uint40(block.timestamp),
            _metadataURI
        );
        
        emit AxiomTypes.FeeCollected(msg.sender, msg.value, recordId);
        
        // Refund excess
        if (msg.value > requiredFee) {
            (bool success,) = payable(msg.sender).call{value: msg.value - requiredFee}("");
            require(success, "Refund failed");
        }
        
        return recordId;
    }

    /**
     * @inheritdoc IAxiomRegistry
     */
    function batchRegister(
        bytes32[] calldata _contentHashes,
        string[] calldata _metadataURIs
    ) external payable override nonReentrant notBanned whenNotPaused returns (bytes32[] memory recordIds) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Validate input
        if (_contentHashes.length != _metadataURIs.length) {
            revert AxiomTypes.ArrayLengthMismatch();
        }
        
        if (_contentHashes.length > s.maxBatchSize) {
            revert AxiomTypes.BatchSizeExceeded(_contentHashes.length, s.maxBatchSize);
        }
        
        // Calculate total fee
        uint256 feePerItem = _getFee(msg.sender);
        uint256 totalFee = feePerItem * _contentHashes.length;
        
        if (msg.value < totalFee) {
            revert AxiomTypes.InsufficientFee(msg.value, totalFee);
        }
        
        recordIds = new bytes32[](_contentHashes.length);
        
        for (uint256 i = 0; i < _contentHashes.length; i++) {
            bytes32 recordId = AxiomStorage.generateRecordId(_contentHashes[i], msg.sender);
            
            // Skip if already exists (don't revert entire batch)
            if (AxiomStorage.recordExists(recordId)) {
                continue;
            }
            
            s.records[recordId] = AxiomTypes.AxiomRecord({
                issuer: msg.sender,
                timestamp: uint40(block.timestamp),
                status: AxiomTypes.ContentStatus.ACTIVE,
                algorithm: AxiomTypes.HashAlgorithm.SHA256,
                contentHash: _contentHashes[i],
                metadataURI: _metadataURIs[i]
            });
            
            s.userRecords[msg.sender].push(recordId);
            s.hashExists[recordId] = true;
            s.totalRecords++;
            recordIds[i] = recordId;
            
            emit AxiomTypes.ContentRegistered(
                recordId,
                msg.sender,
                _contentHashes[i],
                uint40(block.timestamp),
                _metadataURIs[i]
            );
        }
        
        s.totalFeesCollected += msg.value;
        emit AxiomTypes.FeeCollected(msg.sender, msg.value, bytes32(0));
        
        // Refund excess
        if (msg.value > totalFee) {
            (bool success,) = payable(msg.sender).call{value: msg.value - totalFee}("");
            require(success, "Refund failed");
        }
        
        return recordIds;
    }

    /**
     * @inheritdoc IAxiomRegistry
     */
    function revoke(bytes32 _recordId, string calldata _reason) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Check record exists
        if (!AxiomStorage.recordExists(_recordId)) {
            revert AxiomTypes.ContentNotFound(_recordId);
        }
        
        AxiomTypes.AxiomRecord storage record = s.records[_recordId];
        
        // Only issuer can revoke
        if (record.issuer != msg.sender) {
            revert AxiomTypes.NotIssuer(msg.sender, record.issuer);
        }
        
        // Check not already revoked
        if (record.status == AxiomTypes.ContentStatus.REVOKED) {
            revert AxiomTypes.ContentAlreadyRevoked(_recordId);
        }
        
        // Update status
        record.status = AxiomTypes.ContentStatus.REVOKED;
        
        emit AxiomTypes.ContentRevoked(_recordId, msg.sender, _reason);
    }

    // ============ View Functions ============

    /**
     * @inheritdoc IAxiomRegistry
     */
    function verify(
        bytes32 _contentHash,
        address _claimedIssuer
    ) external view override returns (bool isValid, AxiomTypes.AxiomRecord memory record) {
        bytes32 recordId = AxiomStorage.generateRecordId(_contentHash, _claimedIssuer);
        
        if (!AxiomStorage.recordExists(recordId)) {
            return (false, record);
        }
        
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        record = s.records[recordId];
        
        // Content is valid only if status is ACTIVE
        isValid = (record.status == AxiomTypes.ContentStatus.ACTIVE);
        
        return (isValid, record);
    }

    /**
     * @inheritdoc IAxiomRegistry
     */
    function getRecord(bytes32 _recordId) 
        external view override returns (AxiomTypes.AxiomRecord memory record) 
    {
        if (!AxiomStorage.recordExists(_recordId)) {
            revert AxiomTypes.ContentNotFound(_recordId);
        }
        
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.records[_recordId];
    }

    /**
     * @inheritdoc IAxiomRegistry
     */
    function getRecordsByIssuer(address _issuer) 
        external view override returns (bytes32[] memory recordIds) 
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.userRecords[_issuer];
    }

    /**
     * @inheritdoc IAxiomRegistry
     */
    function getTotalRecords() external view override returns (uint256 count) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.totalRecords;
    }

    // ============ Internal Functions ============

    /**
     * @dev Get fee for a specific user
     */
    function _getFee(address _user) internal view returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (s.isEnterprise[_user] && s.enterpriseRates[_user] > 0) {
            return s.enterpriseRates[_user];
        }
        
        return s.baseFee;
    }
}
