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
 *      - Ownership verification via ZK proofs (Groth16)
 *      - GDPR-compliant metadata erasure
 *      - Dependency-injected ZK verifier (production: Groth16Verifier, test: MockVerifier)
 *
 *      Storage: Uses its own Diamond storage slot for privacy-specific data
 *      (same pattern as AxiomDIDRegistry), plus shared AxiomStorage for
 *      cross-facet state (verifier address).
 *
 *      ZK Proof Flow:
 *      1. Caller passes proof as ABI-encoded bytes: abi.encode(uint[2] a, uint[2][2] b, uint[2] c)
 *      2. Facet decodes the proof into Groth16 components (a, b, c)
 *      3. Facet constructs public inputs array from commitment/nullifier/contentHash
 *      4. Facet calls IZKVerifier(verifierAddr).verifyProof(a, b, c, inputs)
 *      5. The verifier address determines behavior (real math vs mock)
 *
 *      CRITICAL: All state stored via Diamond storage pattern. No state variables
 *      in this contract.
 */
contract AxiomPrivacyFacet {
    // ═══════════════════════════════════════════════════════════════════════════
    //                              CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════════

    bytes32 public constant GDPR_ORACLE_ROLE = keccak256("GDPR_ORACLE_ROLE");
    bytes32 public constant ADMIN_ROLE = 0x00;
    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 private constant PUBLIC_INPUT_DOMAIN = keccak256("axiom.protocol.privacy.public-inputs.v1");
    bytes32 private constant COMMITMENT_SIGNAL = keccak256("commitment");
    bytes32 private constant NULLIFIER_SIGNAL = keccak256("nullifier");
    bytes32 private constant CONTENT_SIGNAL = keccak256("content");
    bytes32 private constant REGISTER_PURPOSE = keccak256("register");
    bytes32 private constant OWNERSHIP_PURPOSE = keccak256("ownership");
    bytes32 private constant ERASURE_PURPOSE = keccak256("erasure");

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
        require(IAccessControl(address(this)).hasRole(role, msg.sender), "PrivacyFacet: Missing required role");
        _;
    }

    modifier whenNotPaused() {
        require(!AxiomStorage.getStorage().paused, "Protocol is paused");
        _;
    }

    modifier notBanned() {
        if (AxiomStorage.getStorage().bannedAddresses[msg.sender]) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        _;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          PRIVATE REGISTRATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Register content privately using ZK proof of ownership
     * @dev The commitment hides the user's identity while proving ownership.
     *      The proof must be ABI-encoded Groth16 components:
     *      abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c)
     *
     * @param _contentHash SHA-256 hash of the content
     * @param _commitment ZK commitment to user's identity
     * @param _nullifierHash Hash of nullifier for double-spend protection
     * @param _zkProof ABI-encoded Groth16 proof (a, b, c)
     * @param _metadataURI IPFS/Arweave link to metadata
     * @return recordId Unique identifier for the private record
     */
    function privateRegister(
        bytes32 _contentHash,
        bytes32 _commitment,
        bytes32 _nullifierHash,
        bytes calldata _zkProof,
        string calldata _metadataURI
    ) external payable nonReentrant whenNotPaused notBanned returns (bytes32 recordId) {
        PrivacyStorage storage ps = _getPrivacyStorage();

        require(msg.value == 0, "PrivacyFacet: ETH not accepted");

        // Validate inputs
        require(_contentHash != bytes32(0), "PrivacyFacet: Zero content hash");
        require(_commitment != bytes32(0), "PrivacyFacet: Zero commitment");
        require(_nullifierHash != bytes32(0), "PrivacyFacet: Zero nullifier");
        require(!ps.contentHashExists[_contentHash], "PrivacyFacet: Content already registered");

        // Prevent nullifier reuse (double-registration)
        if (ps.nullifiers[_nullifierHash]) {
            revert AxiomTypesV2.NullifierAlreadyUsed(_nullifierHash);
        }

        // Verify ZK proof
        if (!_verifyProof(_zkProof, _commitment, _nullifierHash, _contentHash, REGISTER_PURPOSE, msg.sender)) {
            revert AxiomTypesV2.InvalidZKProof();
        }

        // Generate unique record ID
        recordId = keccak256(abi.encodePacked(_contentHash, _commitment, block.timestamp, ps.totalRecords++));

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

        emit AxiomTypesV2.PrivateContentRegistered(recordId, _commitment, _nullifierHash, uint40(block.timestamp));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          OWNERSHIP VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify ownership of private content using ZK proof
     * @dev Proves claimant owns content without revealing wallet address.
     *      Decodes the ABI-encoded Groth16 proof and verifies it against
     *      the configured IZKVerifier contract.
     *
     * @param _recordId Private record ID to verify ownership of
     * @param _commitment The commitment being verified
     * @param _zkProof ABI-encoded Groth16 proof (a, b, c)
     * @return isOwner Whether proof is valid (claimant is owner)
     */
    function verifyOwnership(bytes32 _recordId, bytes32 _commitment, bytes calldata _zkProof)
        external
        view
        returns (bool isOwner)
    {
        PrivacyStorage storage ps = _getPrivacyStorage();
        AxiomTypesV2.PrivateRecord storage record = ps.records[_recordId];

        // Record must exist
        if (record.timestamp == 0) return false;

        // Commitment must match
        if (record.commitment != _commitment) return false;

        // Verify proof via the configured ZK verifier
        return _verifyOwnershipProof(_zkProof, record, OWNERSHIP_PURPOSE, msg.sender);
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
    function requestErasure(bytes32 _recordId, bytes calldata _ownershipProof)
        external
        whenNotPaused
        returns (bytes32 requestId)
    {
        PrivacyStorage storage ps = _getPrivacyStorage();
        AxiomTypesV2.PrivateRecord storage record = ps.records[_recordId];

        if (record.timestamp == 0) {
            revert AxiomTypesV2.ContentNotFound(_recordId);
        }
        if (record.metadataDeleted) revert AxiomTypesV2.OperationNotPermitted();

        // Verify ownership proof
        if (!_verifyOwnershipProof(_ownershipProof, record, ERASURE_PURPOSE, msg.sender)) {
            revert AxiomTypesV2.InvalidZKProof();
        }

        requestId = keccak256(abi.encode(PUBLIC_INPUT_DOMAIN, ERASURE_PURPOSE, _recordId));

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
    function confirmErasure(bytes32 _requestId, bytes32 _proofOfCompliance) external onlyRole(GDPR_ORACLE_ROLE) {
        require(_proofOfCompliance != bytes32(0), "PrivacyFacet: Zero compliance proof");
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

        emit AxiomTypesV2.GDPRErasureProcessed(req.recordId, _requestId, uint40(block.timestamp));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          QUERY FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get private record information
     * @param _recordId Private record ID
     * @return record PrivateRecord struct
     */
    function getPrivateRecord(bytes32 _recordId) external view returns (AxiomTypesV2.PrivateRecord memory) {
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
    function getGDPRRequest(bytes32 _requestId) external view returns (AxiomTypesV2.GDPRRequest memory) {
        PrivacyStorage storage ps = _getPrivacyStorage();
        return ps.gdprRequests[_requestId];
    }

    /**
     * @notice Get records associated with a commitment
     * @param _commitment Commitment to look up
     * @return recordIds Array of record IDs
     */
    function getRecordsByCommitment(bytes32 _commitment) external view returns (bytes32[] memory) {
        PrivacyStorage storage ps = _getPrivacyStorage();
        return ps.commitmentToRecords[_commitment];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ZK VERIFIER MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Set the ZK verifier contract address (admin only)
     * @dev In production, set this to the deployed Groth16Verifier address.
     *      In tests, set this to MockVerifier for functional testing.
     *      This is the ONLY way to control verification behavior —
     *      no backdoor flags exist in this contract.
     *
     * @param _verifier Address of the new IZKVerifier-compatible contract
     */
    function setZKVerifier(address _verifier) external onlyRole(ADMIN_ROLE) {
        require(_verifier == address(0) || _verifier.code.length != 0, "PrivacyFacet: Verifier has no code");
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        address oldVerifier = s.privacyVerifier;
        s.privacyVerifier = _verifier;
        s.privacyVerifierProductionApproved = false;
        emit ZKVerifierUpdated(oldVerifier, _verifier);
    }

    /**
     * @notice Approve the configured verifier for non-local deployments.
     * @dev The verifier must advertise an exact three-input schema and explicitly
     *      report that its verification key is production ready.
     */
    function approveZKVerifierForProduction() external onlyRole(ADMIN_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        address verifier = s.privacyVerifier;
        require(verifier != address(0), "PrivacyFacet: No verifier configured");

        (bool countOk, bytes memory countData) = verifier.staticcall(abi.encodeWithSignature("NUM_PUBLIC_INPUTS()"));
        require(
            countOk && countData.length >= 32 && abi.decode(countData, (uint256)) == 3,
            "PrivacyFacet: Unsupported public input schema"
        );

        (bool readyOk, bytes memory readyData) = verifier.staticcall(abi.encodeWithSignature("PRODUCTION_READY()"));
        require(
            readyOk && readyData.length >= 32 && abi.decode(readyData, (bool)),
            "PrivacyFacet: Verifier is not production ready"
        );

        s.privacyVerifierProductionApproved = true;
        emit ZKVerifierProductionApproved(verifier);
    }

    function isZKVerifierProductionApproved() external view returns (bool) {
        return AxiomStorage.getStorage().privacyVerifierProductionApproved;
    }

    /**
     * @notice Get the current ZK verifier address
     * @return verifier Address of the configured verifier contract
     */
    function getZKVerifier() external view returns (address) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.privacyVerifier;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ZK PROOF VERIFICATION (INTERNAL)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Verify a Groth16 ZK proof for private registration
     *
     *      Flow:
     *      1. Require that a verifier contract is configured
     *      2. ABI-decode the proof bytes into Groth16 components (a, b, c)
     *      3. Domain-separate and map each value into the BN254 scalar field
     *      4. Call IZKVerifier.verifyProof(a, b, c, inputs)
     *
     *      The verifier contract determines whether real pairing math is checked
     *      (Groth16Verifier) or proof passes unconditionally (MockVerifier).
     *
     * @param _proof ABI-encoded proof: abi.encode(uint256[2], uint256[2][2], uint256[2])
     * @param _commitment ZK commitment from the registrant
     * @param _nullifierHash Nullifier hash for double-spend protection
     * @param _contentHash Hash of the content being registered
     * @return True if the proof is valid
     */
    function _verifyProof(
        bytes calldata _proof,
        bytes32 _commitment,
        bytes32 _nullifierHash,
        bytes32 _contentHash,
        bytes32 _purpose,
        address _claimant
    ) internal view returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        _requireVerifierAllowed(s);

        // Decode the ABI-encoded Groth16 proof components
        if (_proof.length != 256) return false;
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(_proof, (uint256[2], uint256[2][2], uint256[2]));

        uint256[] memory inputs = _publicInputs(_commitment, _nullifierHash, _contentHash, _purpose, _claimant);

        return IZKVerifier(s.privacyVerifier).verifyProof(a, b, c, inputs);
    }

    /**
     * @dev View-safe proof verification for ownership checks
     *
     *      Uses the same three domain-separated, field-safe public inputs as
     *      registration. The proving circuit must apply this exact transform.
     *
     * @param _proof ABI-encoded proof: abi.encode(uint256[2], uint256[2][2], uint256[2])
     * @param _record Private record whose three public signals are verified
     * @return True if the proof is valid
     */
    function _verifyOwnershipProof(
        bytes calldata _proof,
        AxiomTypesV2.PrivateRecord storage _record,
        bytes32 _purpose,
        address _claimant
    ) internal view returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        _requireVerifierAllowed(s);

        // Decode the ABI-encoded Groth16 proof components
        if (_proof.length != 256) return false;
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(_proof, (uint256[2], uint256[2][2], uint256[2]));

        uint256[] memory inputs =
            _publicInputs(_record.commitment, _record.nullifierHash, _record.contentHash, _purpose, _claimant);

        return IZKVerifier(s.privacyVerifier).verifyProof(a, b, c, inputs);
    }

    function _publicInputs(
        bytes32 _commitment,
        bytes32 _nullifierHash,
        bytes32 _contentHash,
        bytes32 _purpose,
        address _claimant
    ) internal pure returns (uint256[] memory inputs) {
        inputs = new uint256[](3);
        inputs[0] = _toField(COMMITMENT_SIGNAL, _commitment, _purpose, _claimant);
        inputs[1] = _toField(NULLIFIER_SIGNAL, _nullifierHash, _purpose, _claimant);
        inputs[2] = _toField(CONTENT_SIGNAL, _contentHash, _purpose, _claimant);
    }

    function _toField(bytes32 _signalDomain, bytes32 _value, bytes32 _purpose, address _claimant)
        internal
        pure
        returns (uint256)
    {
        return uint256(keccak256(abi.encode(PUBLIC_INPUT_DOMAIN, _purpose, _claimant, _signalDomain, _value)))
            % SNARK_SCALAR_FIELD;
    }

    function _requireVerifierAllowed(AxiomStorage.Storage storage s) internal view {
        require(s.privacyVerifier != address(0), "PrivacyFacet: No verifier configured");
        require(
            block.chainid == 31337 || s.privacyVerifierProductionApproved,
            "PrivacyFacet: Verifier not approved for production"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                              EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    event ZKVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    event ZKVerifierProductionApproved(address indexed verifier);

    event GDPRErasureRequested(bytes32 indexed requestId, bytes32 indexed recordId, uint40 requestedAt);
}
