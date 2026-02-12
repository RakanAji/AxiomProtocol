// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";
import {IZKVerifier} from "../interfaces/IZKVerifier.sol";

// Minimal interface for checking roles via delegatecall context
interface IAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

/**
 * @title AxiomPrivacyFacet
 * @author Axiom Protocol Team
 * @notice Diamond Facet for Privacy-Preserving Content Registration using ZK Proofs
 * @dev Stateless facet executed via delegatecall from AxiomRouter.
 *      
 *      Features:
 *      - Private content registration with ZK commitments & nullifiers
 *      - Ownership verification via ZK proofs
 *      - GDPR-compliant metadata erasure
 *      - Mock ZK verifier for testing (proof == bytes("valid"))
 *      
 *      Storage: Uses its own Diamond storage slot for privacy-specific data
 *      (same pattern as AxiomDIDRegistry), plus shared AxiomStorage for
 *      cross-facet state (verifier address).
 *      
 *      CRITICAL: All state stored via Diamond storage pattern. No state variables
 *      in this contract.
 */
contract AxiomPrivacyFacet {
    // ═══════════════════════════════════════════════════════════════════════════
    //                              CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════════

    bytes32 public constant GDPR_ORACLE_ROLE = keccak256("GDPR_ORACLE_ROLE");

    /// @dev Keccak256 of the valid mock proof for testing
    bytes32 private constant VALID_PROOF_HASH = keccak256(bytes("valid"));

    // ═══════════════════════════════════════════════════════════════════════════
    //                          DIAMOND STORAGE
    // ═══════════════════════════════════════════════════════════════════════════

    /// @dev Storage slot for privacy facet (Diamond pattern)
    bytes32 private constant PRIVACY_STORAGE_SLOT = keccak256("axiom.privacy.facet.storage.v1");

    struct PrivacyStorage {
        /// @notice Maps record ID -> PrivateRecord
        mapping(bytes32 => AxiomTypesV2.PrivateRecord) records;
        
        /// @notice Maps nullifier hash -> used status
        mapping(bytes32 => bool) nullifiers;
        
        /// @notice Maps commitment -> List of record IDs (for access request)
        mapping(bytes32 => bytes32[]) commitmentToRecords;
        
        /// @notice Maps content hash -> exists (for duplicate checking)
        mapping(bytes32 => bool) contentHashExists;
        
        /// @notice Maps request ID -> GDPRRequest
        mapping(bytes32 => AxiomTypesV2.GDPRRequest) gdprRequests;
        
        /// @notice Total private records
        uint256 totalRecords;
    }

    function _getPrivacyStorage() internal pure returns (PrivacyStorage storage s) {
        bytes32 slot = PRIVACY_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                              MODIFIERS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Reentrancy protection using shared storage
     */
    modifier nonReentrant() {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        require(s.reentrancyStatus != 2, "ReentrancyGuard: reentrant call");
        s.reentrancyStatus = 2;
        _;
        s.reentrancyStatus = 1;
    }

    /**
     * @dev Check role via Router's AccessControl (delegatecall context)
     */
    modifier onlyRole(bytes32 role) {
        require(
            IAccessControl(address(this)).hasRole(role, msg.sender),
            "PrivacyFacet: Missing required role"
        );
        _;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          PRIVATE REGISTRATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Register content privately using ZK proof of ownership
     * @dev The commitment hides the user's identity while proving ownership.
     *      Mock verifier: proof is valid if keccak256(proof) == keccak256("valid")
     *      OR if an external IZKVerifier is configured and returns true.
     *
     * @param _contentHash SHA-256 hash of the content
     * @param _commitment ZK commitment to user's identity
     * @param _nullifierHash Hash of nullifier for double-spend protection
     * @param _zkProof Serialized ZK proof (or mock proof bytes("valid"))
     * @param _metadataURI IPFS/Arweave link to metadata
     * @return recordId Unique identifier for the private record
     */
    function privateRegister(
        bytes32 _contentHash,
        bytes32 _commitment,
        bytes32 _nullifierHash,
        bytes calldata _zkProof,
        string calldata _metadataURI
    ) external payable nonReentrant returns (bytes32 recordId) {
        PrivacyStorage storage ps = _getPrivacyStorage();

        // Validate inputs
        require(_contentHash != bytes32(0), "PrivacyFacet: Zero content hash");
        require(_commitment != bytes32(0), "PrivacyFacet: Zero commitment");

        // Prevent nullifier reuse (double-registration)
        if (ps.nullifiers[_nullifierHash]) {
            revert AxiomTypesV2.NullifierAlreadyUsed(_nullifierHash);
        }

        // Verify ZK proof
        if (!_verifyProof(_zkProof, _commitment, _nullifierHash, _contentHash)) {
            revert AxiomTypesV2.InvalidZKProof();
        }

        // Generate unique record ID
        recordId = keccak256(
            abi.encodePacked(
                _contentHash, 
                _commitment, 
                block.timestamp, 
                ps.totalRecords++
            )
        );

        // Store private record
        ps.records[recordId] = AxiomTypesV2.PrivateRecord({
            contentHash: _contentHash,
            commitment: _commitment,
            nullifierHash: _nullifierHash,
            timestamp: uint40(block.timestamp),
            status: AxiomTypesV2.ContentStatus.ACTIVE,
            metadataDeleted: false,
            metadataURI: _metadataURI
        });

        // Mark nullifier as used
        ps.nullifiers[_nullifierHash] = true;
        
        // Track content hash for duplicate checking
        ps.contentHashExists[_contentHash] = true;
        
        // Link commitment to record
        ps.commitmentToRecords[_commitment].push(recordId);

        emit AxiomTypesV2.PrivateContentRegistered(
            recordId, 
            _commitment, 
            _nullifierHash, 
            uint40(block.timestamp)
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          OWNERSHIP VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify ownership of private content using ZK proof
     * @dev Proves claimant owns content without revealing wallet address.
     *      Mock logic: proof is valid if keccak256(proof) == keccak256("valid").
     *
     * @param _recordId Private record ID to verify ownership of
     * @param _commitment The commitment being verified
     * @param _zkProof ZK proof of knowledge of commitment preimage
     * @return isOwner Whether proof is valid (claimant is owner)
     */
    function verifyOwnership(
        bytes32 _recordId,
        bytes32 _commitment,
        bytes calldata _zkProof
    ) external view returns (bool isOwner) {
        PrivacyStorage storage ps = _getPrivacyStorage();
        AxiomTypesV2.PrivateRecord storage record = ps.records[_recordId];
        
        // Record must exist
        if (record.timestamp == 0) return false;
        
        // Commitment must match
        if (record.commitment != _commitment) return false;

        // Verify proof (mock or real)
        return _verifyProofView(_zkProof, _commitment);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          GDPR COMPLIANCE
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Request erasure of personal data (GDPR Article 17)
     * @dev Only erases off-chain metadata URI; on-chain hashes remain
     * @param _recordId Record ID for which to request erasure
     * @param _ownershipProof ZK proof proving caller owns the content
     * @return requestId Unique ID for tracking the erasure request
     */
    function requestErasure(
        bytes32 _recordId,
        bytes calldata _ownershipProof
    ) external returns (bytes32 requestId) {
        PrivacyStorage storage ps = _getPrivacyStorage();
        AxiomTypesV2.PrivateRecord storage record = ps.records[_recordId];
        
        if (record.timestamp == 0) {
            revert AxiomTypesV2.ContentNotFound(_recordId);
        }

        // Verify ownership proof
        if (!_verifyProofView(_ownershipProof, record.commitment)) {
            revert AxiomTypesV2.InvalidZKProof();
        }

        requestId = keccak256(abi.encodePacked(_recordId, block.timestamp, "ERASURE"));

        // Prevent duplicate requests
        if (ps.gdprRequests[requestId].requestedAt != 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        ps.gdprRequests[requestId] = AxiomTypesV2.GDPRRequest({
            recordId: _recordId,
            requestId: requestId,
            requestType: AxiomTypesV2.GDPRRequestType.ERASURE,
            requestedAt: uint40(block.timestamp),
            processedAt: 0,
            processed: false,
            proofOfCompliance: bytes32(0)
        });

        emit GDPRErasureRequested(requestId, _recordId, uint40(block.timestamp));
    }

    /**
     * @notice Confirm erasure completion (GDPR Oracle only)
     * @param _requestId Erasure request ID
     * @param _proofOfCompliance Hash of off-chain compliance evidence
     */
    function confirmErasure(
        bytes32 _requestId,
        bytes32 _proofOfCompliance
    ) external onlyRole(GDPR_ORACLE_ROLE) {
        PrivacyStorage storage ps = _getPrivacyStorage();
        AxiomTypesV2.GDPRRequest storage req = ps.gdprRequests[_requestId];
        
        if (req.requestedAt == 0) {
            revert AxiomTypesV2.InvalidGDPRRequest(_requestId);
        }
        if (req.processed) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        req.processed = true;
        req.processedAt = uint40(block.timestamp);
        req.proofOfCompliance = _proofOfCompliance;

        // Erase metadata from record
        AxiomTypesV2.PrivateRecord storage record = ps.records[req.recordId];
        record.metadataDeleted = true;
        record.metadataURI = "";

        emit AxiomTypesV2.GDPRErasureProcessed(
            req.recordId,
            _requestId,
            uint40(block.timestamp)
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          QUERY FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get private record information
     * @param _recordId Private record ID
     * @return record PrivateRecord struct
     */
    function getPrivateRecord(bytes32 _recordId) 
        external view returns (AxiomTypesV2.PrivateRecord memory) 
    {
        PrivacyStorage storage ps = _getPrivacyStorage();
        return ps.records[_recordId];
    }

    /**
     * @notice Check if content hash exists
     * @param _contentHash Content hash to check
     * @return exists Whether content has been registered
     */
    function contentExists(bytes32 _contentHash) external view returns (bool) {
        PrivacyStorage storage ps = _getPrivacyStorage();
        return ps.contentHashExists[_contentHash];
    }

    /**
     * @notice Check if nullifier has been used
     * @param _nullifierHash Nullifier hash to check
     * @return used Whether nullifier has been used
     */
    function nullifierUsed(bytes32 _nullifierHash) external view returns (bool) {
        PrivacyStorage storage ps = _getPrivacyStorage();
        return ps.nullifiers[_nullifierHash];
    }

    /**
     * @notice Check if metadata has been deleted (GDPR erasure)
     * @param _recordId Record ID to check
     * @return deleted Whether metadata has been erased
     */
    function isMetadataDeleted(bytes32 _recordId) external view returns (bool) {
        PrivacyStorage storage ps = _getPrivacyStorage();
        return ps.records[_recordId].metadataDeleted;
    }

    /**
     * @notice Get GDPR request details
     * @param _requestId Request ID to query
     * @return request GDPRRequest struct
     */
    function getGDPRRequest(bytes32 _requestId) 
        external view returns (AxiomTypesV2.GDPRRequest memory) 
    {
        PrivacyStorage storage ps = _getPrivacyStorage();
        return ps.gdprRequests[_requestId];
    }

    /**
     * @notice Get records associated with a commitment
     * @param _commitment Commitment to look up
     * @return recordIds Array of record IDs
     */
    function getRecordsByCommitment(bytes32 _commitment)
        external view returns (bytes32[] memory)
    {
        PrivacyStorage storage ps = _getPrivacyStorage();
        return ps.commitmentToRecords[_commitment];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ZK PROOF VERIFICATION (INTERNAL)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Verify ZK proof - supports both mock and external verifier
     *      Mock pattern: proof is valid if keccak256(proof) == keccak256("valid")
     *      External: delegates to IZKVerifier if configured in shared storage
     */
    function _verifyProof(
        bytes calldata _proof,
        bytes32 _commitment,
        bytes32 _nullifierHash,
        bytes32 _contentHash
    ) internal view returns (bool) {
        // Mock verification: proof == bytes("valid")
        if (keccak256(_proof) == VALID_PROOF_HASH) {
            return true;
        }

        // Check for external verifier in shared storage
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        if (s.privacyVerifier != address(0)) {
            uint256[] memory inputs = new uint256[](3);
            inputs[0] = uint256(_commitment);
            inputs[1] = uint256(_nullifierHash);
            inputs[2] = uint256(_contentHash);
            return IZKVerifier(s.privacyVerifier).verifyProof(_proof, inputs);
        }

        return false;
    }

    /**
     * @dev View-safe proof verification (for ownership checks)
     */
    function _verifyProofView(
        bytes calldata _proof,
        bytes32 _commitment
    ) internal view returns (bool) {
        // Mock verification
        if (keccak256(_proof) == VALID_PROOF_HASH) {
            return true;
        }

        // External verifier
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        if (s.privacyVerifier != address(0)) {
            uint256[] memory inputs = new uint256[](1);
            inputs[0] = uint256(_commitment);
            return IZKVerifier(s.privacyVerifier).verifyProof(_proof, inputs);
        }

        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                              EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    event GDPRErasureRequested(
        bytes32 indexed requestId,
        bytes32 indexed recordId,
        uint40 requestedAt
    );
}
