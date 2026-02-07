// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";

/**
 * @title IAxiomDID
 * @author Axiom Protocol Team
 * @notice Interface for Decentralized Identifier (DID) management
 * @dev Compatible with ERC-1056 (Lightweight Identity) and W3C DID Core Specification
 *      
 *      This interface enables:
 *      - Registration of DIDs following did:ethr method
 *      - Delegate authorization for signing on behalf of identities
 *      - Verification level management for KYC/KYB compliance
 *      - DID Document resolution and attribute management
 *
 *      Reference Standards:
 *      - W3C DID Core v1.0: https://www.w3.org/TR/did-core/
 *      - ERC-1056: https://eips.ethereum.org/EIPS/eip-1056
 */
interface IAxiomDID {
    // ═══════════════════════════════════════════════════════════════════════════
    //                          DID REGISTRATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Register a new DID linked to the caller's wallet address
     * @dev The DID string should follow did:ethr format: "did:ethr:{chainId}:{address}"
     *      The DID Document should be a valid JSON-LD document stored on IPFS
     *      
     *      Requirements:
     *      - Caller must not have an existing DID
     *      - DID string must not be empty
     *      - DID Document hash must be non-zero
     *
     *      Emits {DIDRegistered} event
     *
     * @param _did The full DID string (e.g., "did:ethr:1:0x123...")
     * @param _didDocumentHash IPFS hash (CID) of the DID Document JSON
     * @param _publicKeyJwk Public key in JWK format for signature verification
     */
    function registerDID(
        string calldata _did,
        bytes32 _didDocumentHash,
        string calldata _publicKeyJwk
    ) external;

    /**
     * @notice Update an existing DID Document
     * @dev Only the identity owner can update their DID Document
     *      The old document remains accessible via IPFS for audit trail
     *
     *      Requirements:
     *      - Caller must have an existing DID
     *      - DID must be active (not revoked)
     *
     *      Emits {DIDAttributeChanged} event
     *
     * @param _newDocumentHash New IPFS hash of updated DID Document
     */
    function updateDIDDocument(bytes32 _newDocumentHash) external;

    /**
     * @notice Set service endpoint for DID (e.g., content delivery URL)
     * @dev Service endpoints allow discovery of services associated with the DID
     *
     *      Emits {DIDAttributeChanged} event
     *
     * @param _serviceEndpoint URL of the service endpoint
     */
    function setServiceEndpoint(string calldata _serviceEndpoint) external;

    /**
     * @notice Revoke (deactivate) a DID permanently
     * @dev This action is irreversible. The DID cannot be re-activated.
     *      Historic records associated with this DID remain valid.
     *
     *      Requirements:
     *      - Caller must be the DID owner
     *      - DID must currently be active
     *
     *      Emits {DIDAttributeChanged} event with deactivation marker
     *
     */
    function revokeDID() external;

    // ═══════════════════════════════════════════════════════════════════════════
    //                          DELEGATE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Add a delegate authorized to act on behalf of this identity
     * @dev Delegates can sign content registrations on behalf of the identity
     *      Common delegate types:
     *      - "sigAuth": Can sign authentication proofs
     *      - "veriKey": Can sign verifiable credentials
     *      - "axiomReg": Can register content on behalf of identity
     *
     *      Requirements:
     *      - Caller must be the DID owner
     *      - Delegate address must not be zero
     *      - Validity period must be in the future
     *
     *      Emits {DIDDelegateChanged} event (ERC-1056 standard)
     *
     * @param _delegate Address of the delegate
     * @param _delegateType Type of delegation (keccak256 hash of type string)
     * @param _validity Duration in seconds for delegation validity
     */
    function addDelegate(
        address _delegate,
        bytes32 _delegateType,
        uint256 _validity
    ) external;

    /**
     * @notice Revoke a delegate's authorization
     * @dev Immediately invalidates the delegate regardless of original validity period
     *
     *      Requirements:
     *      - Caller must be the DID owner
     *      - Delegate must exist for the specified type
     *
     *      Emits {DIDDelegateChanged} event with validity = 0
     *
     * @param _delegate Address of the delegate to revoke
     * @param _delegateType Type of delegation being revoked
     */
    function revokeDelegate(address _delegate, bytes32 _delegateType) external;

    /**
     * @notice Check if a delegate is currently valid for an identity
     * @dev Returns true only if delegate was added and validity period hasn't expired
     *
     * @param _identity The identity (DID owner) address
     * @param _delegateType Type of delegation to check
     * @param _delegate Address of the potential delegate
     * @return isValid Whether the delegate is currently authorized
     */
    function validDelegate(
        address _identity,
        bytes32 _delegateType,
        address _delegate
    ) external view returns (bool isValid);

    /**
     * @notice Get all active delegates for an identity
     * @param _identity The identity address
     * @return delegates Array of active DIDDelegate structs
     */
    function getDelegates(address _identity) 
        external view returns (AxiomTypesV2.DIDDelegate[] memory delegates);

    // ═══════════════════════════════════════════════════════════════════════════
    //                       VERIFICATION LEVEL MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Set verification level for an identity (requires VERIFIER_ROLE)
     * @dev Verification is performed off-chain, this function records the result
     *      
     *      Verification levels:
     *      - NONE: Self-declared only
     *      - BASIC: Email/phone verified
     *      - ENTERPRISE: Business registration verified (KYB)
     *      - GOVERNMENT: Government ID verified (KYC)
     *
     *      Requirements:
     *      - Caller must have VERIFIER_ROLE
     *      - Identity must have an active DID
     *
     *      Emits {VerificationLevelChanged} event
     *
     * @param _user Address of the identity to verify
     * @param _level New verification level to assign
     */
    function setVerificationLevel(
        address _user,
        AxiomTypesV2.VerificationLevel _level
    ) external;

    /**
     * @notice Get current verification level for an identity
     * @param _user Address to check
     * @return level Current verification level
     */
    function getVerificationLevel(address _user) 
        external view returns (AxiomTypesV2.VerificationLevel level);

    /**
     * @notice Check if identity meets minimum verification requirement
     * @dev Useful for gated features that require certain verification levels
     *
     * @param _user Address to check
     * @param _minLevel Minimum required verification level
     * @return meetsRequirement Whether identity meets or exceeds minimum level
     */
    function meetsVerificationLevel(
        address _user,
        AxiomTypesV2.VerificationLevel _minLevel
    ) external view returns (bool meetsRequirement);

    // ═══════════════════════════════════════════════════════════════════════════
    //                            DID RESOLUTION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Resolve a DID string to its full identity information
     * @dev Returns empty struct if DID not found
     *
     * @param _did The DID string to resolve
     * @return identity Full DIDIdentity struct
     */
    function resolveDID(string calldata _did) 
        external view returns (AxiomTypesV2.DIDIdentity memory identity);

    /**
     * @notice Get DID identity by wallet address
     * @dev Reverse lookup - address to DID
     *
     * @param _user Wallet address to look up
     * @return identity Full DIDIdentity struct
     */
    function getIdentity(address _user) 
        external view returns (AxiomTypesV2.DIDIdentity memory identity);

    /**
     * @notice Check if an address has a registered DID
     * @param _user Address to check
     * @return exists Whether a DID exists for this address
     */
    function hasDID(address _user) external view returns (bool exists);

    /**
     * @notice Check if a DID is currently active (not revoked/expired)
     * @param _user Address of DID owner
     * @return active Whether DID is active
     */
    function isDIDActive(address _user) external view returns (bool active);

    /**
     * @notice Get DID string for an address
     * @dev Convenience function for quick DID lookup
     *
     * @param _user Address to look up
     * @return did The DID string (empty if not registered)
     */
    function getDIDString(address _user) external view returns (string memory did);

    // ═══════════════════════════════════════════════════════════════════════════
    //                      ERC-1056 ATTRIBUTE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Set an attribute for a DID (ERC-1056 compatible)
     * @dev Generic attribute storage following ERC-1056 pattern
     *      Common attribute names:
     *      - "did/pub/Ed25519/veriKey/base64": Public key
     *      - "did/svc/ContentDelivery": Service endpoint
     *
     *      Emits {DIDAttributeChanged} event
     *
     * @param _name Attribute name (hashed for storage)
     * @param _value Attribute value
     * @param _validity How long attribute is valid (seconds)
     */
    function setAttribute(
        bytes32 _name,
        bytes calldata _value,
        uint256 _validity
    ) external;

    /**
     * @notice Revoke an attribute (ERC-1056 compatible)
     * @dev Sets attribute validity to 0 (immediate expiration)
     *
     *      Emits {DIDAttributeChanged} event with validity = 0
     *
     * @param _name Attribute name to revoke
     * @param _value Attribute value to revoke
     */
    function revokeAttribute(bytes32 _name, bytes calldata _value) external;

    // ═══════════════════════════════════════════════════════════════════════════
    //                          SIGNATURE VALIDATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify a signature was made by a valid identity or delegate
     * @dev Used to validate content registration signatures
     *
     * @param _identity The claimed identity (DID owner)
     * @param _hash The message hash that was signed
     * @param _signature The signature to verify
     * @return isValid Whether signature is from identity or valid delegate
     * @return signer The actual signer address
     */
    function verifySignature(
        address _identity,
        bytes32 _hash,
        bytes calldata _signature
    ) external view returns (bool isValid, address signer);

    /**
     * @notice Get the current nonce for an identity (for replay protection)
     * @param _identity The identity address
     * @return nonce Current nonce value
     */
    function nonce(address _identity) external view returns (uint256);

    // ═══════════════════════════════════════════════════════════════════════════
    //                              EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Emitted when a new DID is registered
     * @param identity The wallet address of the DID owner
     * @param did The full DID string
     * @param didDocumentHash IPFS hash of DID Document
     */
    event DIDRegistered(
        address indexed identity,
        string did,
        bytes32 didDocumentHash
    );

    /**
     * @notice Emitted when DID attribute changes (ERC-1056 standard)
     * @param identity The identity address
     * @param name Attribute name (hashed)
     * @param value Attribute value
     * @param validTo Timestamp when attribute expires
     * @param previousChange Block number of previous change
     */
    event DIDAttributeChanged(
        address indexed identity,
        bytes32 indexed name,
        bytes value,
        uint256 validTo,
        uint256 previousChange
    );

    /**
     * @notice Emitted when delegate status changes (ERC-1056 standard)
     * @param identity The identity address
     * @param delegateType Type of delegation
     * @param delegate The delegate address
     * @param validTo Timestamp when delegation expires (0 = revoked)
     * @param previousChange Block number of previous change
     */
    event DIDDelegateChanged(
        address indexed identity,
        bytes32 indexed delegateType,
        address indexed delegate,
        uint256 validTo,
        uint256 previousChange
    );

    /**
     * @notice Emitted when verification level changes
     * @param identity The identity address
     * @param oldLevel Previous verification level
     * @param newLevel New verification level
     * @param verifier Address of the verifier who made the change
     */
    event VerificationLevelChanged(
        address indexed identity,
        AxiomTypesV2.VerificationLevel oldLevel,
        AxiomTypesV2.VerificationLevel newLevel,
        address indexed verifier
    );
}
