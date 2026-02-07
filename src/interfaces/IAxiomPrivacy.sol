// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";

/**
 * @title IAxiomPrivacy
 * @author Axiom Protocol Team
 * @notice Interface for privacy-preserving content registration using Zero-Knowledge Proofs
 * @dev Enables GDPR-compliant content registration with the following properties:
 *      - Wallet addresses are not linked to content on-chain
 *      - Ownership can be proven via ZK proofs without revealing identity
 *      - Metadata can be erased for GDPR "Right to be Forgotten" compliance
 *      - Content hash and timestamp remain immutable for provenance
 *
 *      Cryptographic Approach:
 *      1. User generates secret (s) and nullifier (n) off-chain
 *      2. Commitment C = hash(address, s, n) is stored on-chain
 *      3. User proves knowledge of (address, s, n) via ZK-SNARK
 *      4. Nullifier prevents double-registration of same content
 *
 *      Compatible ZK Systems:
 *      - Groth16 (recommended for low gas cost)
 *      - PLONK (universal setup)
 *      - Circom-based circuits
 */
interface IAxiomPrivacy {
    // ═══════════════════════════════════════════════════════════════════════════
    //                      PRIVATE CONTENT REGISTRATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Register content privately using ZK proof of ownership
     * @dev The commitment hides the user's identity while proving ownership
     *      The nullifier prevents the same identity from double-registering
     *
     *      ZK Circuit Public Inputs:
     *      - commitment (computed from address + secrets)
     *      - nullifierHash (computed from nullifier + contentHash)
     *
     *      ZK Circuit Private Inputs:
     *      - address (user's wallet address)
     *      - secret (random value known only to user)
     *      - nullifier (random value for double-spend protection)
     *
     *      Requirements:
     *      - ZK proof must be valid
     *      - Nullifier hash must not have been used before
     *      - Content hash must be non-zero
     *      - Correct fee must be paid
     *
     *      Emits {PrivateContentRegistered} event
     *
     * @param _contentHash SHA-256 hash of the content
     * @param _commitment ZK commitment to user's identity: hash(address, secret, nullifier)
     * @param _nullifierHash Hash of nullifier and contentHash for double-spend protection
     * @param _zkProof Serialized ZK proof (Groth16 or PLONK format)
     * @param _metadataURI IPFS/Arweave link to metadata (can be deleted for GDPR)
     * @return recordId Unique identifier for the private record
     */
    function privateRegister(
        bytes32 _contentHash,
        bytes32 _commitment,
        bytes32 _nullifierHash,
        bytes calldata _zkProof,
        string calldata _metadataURI
    ) external payable returns (bytes32 recordId);

    /**
     * @notice Batch private registration with multiple ZK proofs
     * @dev More gas efficient than individual registrations
     *
     * @param _contentHashes Array of content hashes
     * @param _commitments Array of commitments
     * @param _nullifierHashes Array of nullifier hashes
     * @param _zkProofs Array of ZK proofs
     * @param _metadataURIs Array of metadata URIs
     * @return recordIds Array of generated record IDs
     */
    function batchPrivateRegister(
        bytes32[] calldata _contentHashes,
        bytes32[] calldata _commitments,
        bytes32[] calldata _nullifierHashes,
        bytes[] calldata _zkProofs,
        string[] calldata _metadataURIs
    ) external payable returns (bytes32[] memory recordIds);

    // ═══════════════════════════════════════════════════════════════════════════
    //                      OWNERSHIP VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify ownership of private content using ZK proof
     * @dev Allows anyone to verify that a claimant owns content without 
     *      revealing their actual wallet address
     *
     *      The proof demonstrates:
     *      "I know (address, secret, nullifier) such that commitment = hash(address, secret, nullifier)"
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
    ) external view returns (bool isOwner);

    /**
     * @notice Generate ownership proof for off-chain verification
     * @dev Returns data needed for off-chain proof generation
     *      The actual proof is generated client-side
     *
     * @param _recordId Record to generate proof for
     * @return commitment The stored commitment
     * @return proofInputs Public inputs needed for proof verification
     */
    function getProofInputs(bytes32 _recordId) 
        external view returns (bytes32 commitment, bytes memory proofInputs);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          GDPR COMPLIANCE
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Request erasure of personal data (GDPR Article 17)
     * @dev Only erases off-chain metadata, not the on-chain content hash
     *      The commitment and nullifier remain for proof of prior registration
     *
     *      Process:
     *      1. User proves ownership via ZK proof
     *      2. Request is recorded on-chain
     *      3. Off-chain oracle unpins metadata from IPFS
     *      4. Confirmation is recorded
     *
     *      Requirements:
     *      - Caller must prove ownership via ZK proof
     *      - Record must not already have erasure processed
     *
     *      Emits {GDPRErasureRequested} event
     *
     * @param _recordId Record ID for which to request erasure
     * @param _ownershipProof ZK proof proving caller owns the content
     * @return requestId Unique ID for tracking the erasure request
     */
    function requestErasure(
        bytes32 _recordId,
        bytes calldata _ownershipProof
    ) external returns (bytes32 requestId);

    /**
     * @notice Confirm erasure completion (called by GDPR Oracle)
     * @dev Only callable by authorized GDPR_ORACLE_ROLE
     *      Marks metadata as deleted on-chain
     *
     *      Requirements:
     *      - Caller must have GDPR_ORACLE_ROLE
     *      - Request must exist and be pending
     *
     *      Emits {GDPRErasureProcessed} event
     *
     * @param _requestId Erasure request ID
     * @param _proofOfCompliance Hash of off-chain compliance evidence
     */
    function confirmErasure(
        bytes32 _requestId,
        bytes32 _proofOfCompliance
    ) external;

    /**
     * @notice Submit GDPR access request (Article 15)
     * @dev Returns all data associated with a commitment
     *
     * @param _commitment User's identity commitment
     * @param _ownershipProof ZK proof of commitment ownership
     * @return recordIds All record IDs associated with this commitment
     */
    function requestAccess(
        bytes32 _commitment,
        bytes calldata _ownershipProof
    ) external view returns (bytes32[] memory recordIds);

    /**
     * @notice Get status of GDPR request
     * @param _requestId Request ID to query
     * @return request Full GDPRRequest struct
     */
    function getGDPRRequest(bytes32 _requestId) 
        external view returns (AxiomTypesV2.GDPRRequest memory request);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          PRIVATE RECORD QUERIES
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get private record information
     * @dev Returns all public information (commitment, hash, timestamp)
     *      Does NOT reveal owner's identity
     *
     * @param _recordId Private record ID
     * @return record PrivateRecord struct
     */
    function getPrivateRecord(bytes32 _recordId) 
        external view returns (AxiomTypesV2.PrivateRecord memory record);

    /**
     * @notice Check if content hash exists (regardless of ownership)
     * @dev Used to check for duplicates - returns true if ANY commitment
     *      has registered this content hash
     *
     * @param _contentHash Content hash to check
     * @return exists Whether content has been registered
     */
    function contentExists(bytes32 _contentHash) external view returns (bool exists);

    /**
     * @notice Check if nullifier has been used
     * @dev Used by off-chain systems to verify before submitting proofs
     *
     * @param _nullifierHash Nullifier hash to check
     * @return used Whether nullifier has been used
     */
    function nullifierUsed(bytes32 _nullifierHash) external view returns (bool used);

    /**
     * @notice Check if metadata has been deleted (GDPR erasure)
     * @param _recordId Record ID to check
     * @return deleted Whether metadata has been erased
     */
    function isMetadataDeleted(bytes32 _recordId) external view returns (bool deleted);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ZK VERIFIER MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get the ZK verifier contract address
     * @dev Verifier is generated from the ZK circuit and deployed separately
     *
     * @return verifier Address of the ZK verifier contract
     */
    function getZKVerifier() external view returns (address verifier);

    /**
     * @notice Set a new ZK verifier (requires ADMIN_ROLE)
     * @dev Used when upgrading the ZK circuit
     *
     * @param _newVerifier Address of new verifier contract
     */
    function setZKVerifier(address _newVerifier) external;

    /**
     * @notice Get supported proof systems
     * @return systems Array of supported proof system identifiers (e.g., "groth16", "plonk")
     */
    function getSupportedProofSystems() external view returns (string[] memory systems);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          COMMITMENT MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Link additional commitment to existing identity (key rotation)
     * @dev Allows users to rotate their secrets while maintaining content ownership
     *
     *      Requirements:
     *      - Must prove ownership of old commitment
     *      - New commitment must not already exist
     *
     * @param _oldCommitment Current commitment
     * @param _newCommitment New commitment to link
     * @param _migrationProof ZK proof linking old and new commitments
     */
    function rotateCommitment(
        bytes32 _oldCommitment,
        bytes32 _newCommitment,
        bytes calldata _migrationProof
    ) external;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Emitted when private content is registered
     * @param recordId Unique record identifier
     * @param commitment ZK commitment (hides identity)
     * @param nullifierHash Double-spend prevention hash
     * @param timestamp Registration timestamp
     */
    event PrivateContentRegistered(
        bytes32 indexed recordId,
        bytes32 indexed commitment,
        bytes32 nullifierHash,
        uint40 timestamp
    );

    /**
     * @notice Emitted when GDPR erasure is requested
     * @param requestId Unique request identifier
     * @param recordId Record to be erased
     * @param requestedAt Request timestamp
     */
    event GDPRErasureRequested(
        bytes32 indexed requestId,
        bytes32 indexed recordId,
        uint40 requestedAt
    );

    /**
     * @notice Emitted when GDPR erasure is processed
     * @param requestId Request that was processed
     * @param recordId Record that was erased
     * @param processedAt Completion timestamp
     * @param proofOfCompliance Hash of compliance evidence
     */
    event GDPRErasureProcessed(
        bytes32 indexed requestId,
        bytes32 indexed recordId,
        uint40 processedAt,
        bytes32 proofOfCompliance
    );

    /**
     * @notice Emitted when commitment is rotated
     * @param oldCommitment Previous commitment
     * @param newCommitment New commitment
     */
    event CommitmentRotated(
        bytes32 indexed oldCommitment,
        bytes32 indexed newCommitment
    );

    /**
     * @notice Emitted when ZK verifier is updated
     * @param oldVerifier Previous verifier address
     * @param newVerifier New verifier address
     */
    event ZKVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );
}
