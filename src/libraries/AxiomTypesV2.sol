// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AxiomTypesV2
 * @author Axiom Protocol Team
 * @notice Enterprise-grade data structures for Axiom Protocol v2.0
 * @dev All structs are gas-optimized using tight variable packing
 *      Supports: W3C DID, C2PA, IPTC/XMP, Programmable IP, Decentralized Disputes
 */
library AxiomTypesV2 {
    // ═══════════════════════════════════════════════════════════════════════════
    //                                  ENUMS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Status of registered content
     * @dev Uses uint8 for gas optimization
     */
    enum ContentStatus {
        ACTIVE,     // 0 - Content is valid and verified
        REVOKED,    // 1 - Content was revoked by issuer
        DISPUTED,   // 2 - Content is under dispute
        BANNED      // 3 - Content banned by arbitration ruling
    }

    /**
     * @notice Supported hash algorithms for future-proofing
     */
    enum HashAlgorithm {
        SHA256,     // 0 - Default algorithm (C2PA standard)
        SHA3_256,   // 1 - Future support
        KECCAK256   // 2 - Native Ethereum hash
    }

    /**
     * @notice Identity verification levels (W3C DID compliance)
     * @dev Higher levels require more rigorous off-chain verification
     */
    enum VerificationLevel {
        NONE,       // 0 - Self-declared identity only
        BASIC,      // 1 - Email/phone verified
        ENTERPRISE, // 2 - Business registration verified (KYB)
        GOVERNMENT  // 3 - Government-issued ID verified (KYC)
    }

    /**
     * @notice Standard license types following Creative Commons + Commercial
     * @dev Mapped to SPDX license identifiers where applicable
     */
    enum LicenseType {
        NONE,                   // 0 - No license attached
        CC0,                    // 1 - Public domain, no restrictions
        CC_BY,                  // 2 - Attribution required
        CC_BY_SA,               // 3 - Attribution + ShareAlike
        CC_BY_NC,               // 4 - Attribution + NonCommercial
        CC_BY_NC_SA,            // 5 - Attribution + NonCommercial + ShareAlike
        CC_BY_ND,               // 6 - Attribution + NoDerivatives
        CC_BY_NC_ND,            // 7 - Attribution + NonCommercial + NoDerivatives
        COMMERCIAL_SINGLE,      // 8 - One-time commercial use
        COMMERCIAL_UNLIMITED,   // 9 - Unlimited commercial use
        EXCLUSIVE,              // 10 - Exclusive rights (one licensee)
        CUSTOM                  // 11 - Custom terms (URI required)
    }

    /**
     * @notice Categories for content disputes
     * @dev Used for routing to appropriate arbitration subcourt
     */
    enum DisputeReason {
        COPYRIGHT_INFRINGEMENT,  // 0 - Content violates copyright
        FALSE_ATTRIBUTION,       // 1 - Wrong creator claimed
        HARMFUL_CONTENT,         // 2 - Illegal/harmful material
        DUPLICATE_REGISTRATION,  // 3 - Already registered by another
        FRAUDULENT_METADATA,     // 4 - Metadata doesn't match content
        TRADEMARK_VIOLATION,     // 5 - Trademark infringement
        PRIVACY_VIOLATION,       // 6 - Contains PII without consent
        OTHER                    // 7 - Freeform reason required
    }

    /**
     * @notice Dispute lifecycle status
     */
    enum DisputeStatus {
        PENDING,            // 0 - Awaiting response from content owner
        EVIDENCE_PERIOD,    // 1 - Both parties submitting evidence
        ARBITRATION,        // 2 - Escalated to external arbitrator
        RESOLVED_VALID,     // 3 - Dispute upheld (challenger wins)
        RESOLVED_INVALID,   // 4 - Dispute rejected (owner wins)
        APPEALED,           // 5 - Ruling appealed
        SETTLED             // 6 - Parties reached settlement
    }

    /**
     * @notice Subscription tier for Account Abstraction paymaster
     */
    enum SubscriptionTier {
        NONE,       // 0 - No subscription (pay-per-use)
        BASIC,      // 1 - 100 registrations/month
        PRO,        // 2 - 1,000 registrations/month
        ENTERPRISE  // 3 - Unlimited, priority bundling
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                              CORE STRUCTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Enhanced content record with C2PA and license support
     * @dev Packed for gas optimization:
     *      Slot 1: issuer (20) + timestamp (5) + status (1) + algorithm (1) + licenseType (1) = 28 bytes
     *      Slot 2: contentHash (32)
     *      Slot 3: manifestHash (32)
     *      Slot 4: didHash (32)
     *      Slot 5+: metadataURI (dynamic)
     */
    struct AxiomRecord {
        address issuer;             // 20 bytes - Wallet address that signed the content
        uint40 timestamp;           // 5 bytes - Block timestamp (enough until year 36,812)
        ContentStatus status;       // 1 byte - Current status of the record
        HashAlgorithm algorithm;    // 1 byte - Hash algorithm used
        LicenseType licenseType;    // 1 byte - Default license type
        bytes32 contentHash;        // 32 bytes - Hash of the content
        bytes32 manifestHash;       // 32 bytes - C2PA manifest hash (0x0 if none)
        bytes32 didHash;            // 32 bytes - Hash of creator's DID (for privacy)
        string metadataURI;         // Dynamic - IPFS/Arweave link to full metadata
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          W3C DID STRUCTS (ERC-1056)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Decentralized Identifier (DID) following W3C DID Core spec
     * @dev Compatible with did:ethr method (ERC-1056)
     *      Packed:
     *      Slot 1: level (1) + isActive (1) + validUntil (5) + registeredAt (5) = 12 bytes
     *      Slot 2+: Mappings and dynamic strings stored separately
     */
    struct DIDIdentity {
        VerificationLevel level;    // 1 byte - Verification level achieved
        bool isActive;              // 1 byte - Whether DID is active (not revoked)
        uint40 validUntil;          // 5 bytes - Expiration timestamp (0 = no expiry)
        uint40 registeredAt;        // 5 bytes - Registration timestamp
        bytes32 didDocumentHash;    // 32 bytes - IPFS hash of DID Document JSON
        string did;                 // Dynamic - Full DID string (e.g., "did:ethr:0x...")
        string publicKeyJwk;        // Dynamic - Public key in JWK format (for verification)
        string serviceEndpoint;     // Dynamic - DID service endpoint URL
    }

    /**
     * @notice Delegate authorization for DID (ERC-1056 compatible)
     * @dev Allows addresses to act on behalf of an identity
     */
    struct DIDDelegate {
        address delegate;           // 20 bytes - Authorized delegate address
        bytes32 delegateType;       // 32 bytes - Type of delegation (e.g., "sigAuth", "veriKey")
        uint40 validUntil;          // 5 bytes - Delegation expiry
        bool isActive;              // 1 byte - Whether delegation is active
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                      C2PA & IPTC/XMP METADATA STRUCTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice C2PA Manifest reference with IPTC/XMP compatibility
     * @dev This struct stores on-chain references; full manifest stored on IPFS
     *      IPTC Core fields are hashed for on-chain verification without storage cost
     *      
     *      Packed:
     *      Slot 1: signedAt (5) + assertionCount (2) + hasIPTC (1) + hasXMP (1) = 9 bytes
     *      Slot 2: manifestHash (32)
     *      Slot 3: iptcHash (32)
     *      Slot 4+: manifestURI, signature (dynamic)
     */
    struct C2PAMetadata {
        uint40 signedAt;            // 5 bytes - Manifest signature timestamp
        uint16 assertionCount;      // 2 bytes - Number of assertions in manifest
        bool hasIPTC;               // 1 byte - Whether IPTC metadata is embedded
        bool hasXMP;                // 1 byte - Whether XMP metadata is embedded
        bytes32 manifestHash;       // 32 bytes - SHA-256 of complete C2PA manifest
        bytes32 iptcHash;           // 32 bytes - Hash of IPTC metadata subset
        string manifestURI;         // Dynamic - IPFS CID of full C2PA manifest
        string claimGenerator;      // Dynamic - Software that created claim (e.g., "Axiom SDK v2.0")
        bytes signature;            // Dynamic - ECDSA signature of manifest
    }

    /**
     * @notice IPTC Core metadata fields (stored off-chain, hashes on-chain)
     * @dev Following IPTC Photo Metadata Standard 2021.1
     *      This struct is for documentation/SDK use - actual data stored as JSON on IPFS
     *      
     *      Required IPTC fields for news agency compatibility:
     *      - Creator (Iptc4xmpCore:Creator)
     *      - Credit Line (photoshop:Credit)
     *      - Copyright Notice (dc:rights)
     *      - Source (photoshop:Source)
     *      
     *      Additional fields for full compatibility:
     *      - Date Created, Description, Keywords, etc.
     */
    struct IPTCMetadata {
        string creator;             // Creator/Byline name
        string creditLine;          // Credit line for publication
        string copyrightNotice;     // Full copyright notice (e.g., "© 2026 Reuters")
        string source;              // Original source/provider
        string headline;            // Short synopsis/headline
        string captionWriter;       // Caption writer identifier
        string dateCreated;         // ISO 8601 date (YYYY-MM-DD)
        string city;                // City of content origin
        string country;             // Country name
        string countryCode;         // ISO 3166-1 alpha-3 country code
    }

    /**
     * @notice XMP Rights metadata (Adobe standard, stored off-chain)
     * @dev Following XMP Specification Part 1
     */
    struct XMPRights {
        string webStatement;        // URL to rights statement
        string usageTerms;          // Human-readable usage terms
        bool marked;                // Whether content is rights-marked
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                        PROGRAMMABLE IP LICENSE STRUCTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Full license definition for programmable IP
     * @dev Each license can be minted as ERC-721 NFT
     *      
     *      Packed:
     *      Slot 1: licensor (20) + licenseType (1) + royaltyBps (2) + exclusive (1) + sublicensable (1) + transferable (1) + active (1) = 27 bytes
     *      Slot 2: licensee (20) + validFrom (5) + validUntil (5) = 30 bytes
     *      Slot 3: recordId (32)
     *      Slot 4: price (32)
     *      Slot 5: paymentToken (20) = 20 bytes
     *      Slot 6+: customTermsURI, territoryRestrictions (dynamic)
     */
    struct License {
        // Core identifiers
        bytes32 recordId;           // 32 bytes - Parent content record ID
        address licensor;           // 20 bytes - Content owner granting license
        address licensee;           // 20 bytes - License holder (0x0 if available)
        address paymentToken;       // 20 bytes - Payment token (0x0 for ETH)
        
        // License terms
        LicenseType licenseType;    // 1 byte - Type of license
        uint16 royaltyBps;          // 2 bytes - Royalty basis points (e.g., 250 = 2.5%)
        bool exclusive;             // 1 byte - If true, only one licensee allowed
        bool sublicensable;         // 1 byte - Can licensee create sub-licenses
        bool transferable;          // 1 byte - Can license NFT be transferred
        bool active;                // 1 byte - Whether license is currently active
        
        // Validity period
        uint40 validFrom;           // 5 bytes - License start timestamp
        uint40 validUntil;          // 5 bytes - License end timestamp (0 = perpetual)
        
        // Commercial terms
        uint256 price;              // 32 bytes - License price in payment token
        
        // Extended terms (stored as URIs for gas efficiency)
        string customTermsURI;      // Dynamic - IPFS link to full license terms
        string territoryRestrictions; // Dynamic - JSON of geographic restrictions
    }

    /**
     * @notice Royalty distribution configuration (ERC-2981 extended)
     * @dev Supports multiple recipients with percentage splits
     */
    struct RoyaltySplit {
        address[] recipients;       // Array of royalty recipients
        uint16[] shares;            // Shares in basis points (must sum to 10000)
        bool autoDistribute;        // If true, distribute on each sale; else on claim
    }

    /**
     * @notice License purchase record
     * @dev Tracks each license purchase for audit trail
     */
    struct LicensePurchase {
        uint256 licenseId;          // License template ID
        uint256 tokenId;            // Minted NFT token ID
        address buyer;              // Purchaser address
        uint256 pricePaid;          // Actual price paid
        uint40 purchasedAt;         // Purchase timestamp
        uint40 expiresAt;           // Expiration (copied from license)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                         DISPUTE & ARBITRATION STRUCTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Dispute record for decentralized arbitration
     * @dev Integrates with Kleros, Aragon Court, or UMA protocols
     *      
     *      Packed:
     *      Slot 1: challenger (20) + reason (1) + status (1) = 22 bytes
     *      Slot 2: recordId (32)
     *      Slot 3: stakeAmount (32)
     *      Slot 4: createdAt (5) + deadline (5) + resolvedAt (5) = 15 bytes
     *      Slot 5: arbitrator (20) = 20 bytes
     *      Slot 6: externalDisputeId (32)
     *      Slot 7+: evidenceURI, responseURI (dynamic)
     */
    struct Dispute {
        // Core identifiers
        bytes32 disputeId;          // 32 bytes - Unique dispute identifier
        bytes32 recordId;           // 32 bytes - Content being disputed
        bytes32 externalDisputeId;  // 32 bytes - ID in external arbitrator (Kleros/Aragon)
        
        // Parties
        address challenger;         // 20 bytes - Who initiated dispute
        address arbitrator;         // 20 bytes - External arbitration protocol address
        
        // Dispute details
        DisputeReason reason;       // 1 byte - Category of dispute
        DisputeStatus status;       // 1 byte - Current status
        
        // Staking
        uint256 stakeAmount;        // 32 bytes - Locked stake from challenger
        address stakeToken;         // 20 bytes - Token used for stake
        
        // Timeline
        uint40 createdAt;           // 5 bytes - Dispute creation timestamp
        uint40 deadline;            // 5 bytes - Response/resolution deadline
        uint40 resolvedAt;          // 5 bytes - When dispute was resolved (0 if pending)
        
        // Evidence
        string evidenceURI;         // Dynamic - IPFS link to challenger's evidence
        string responseURI;         // Dynamic - IPFS link to owner's response
    }

    /**
     * @notice Staking configuration for dispute mechanics
     * @dev Configurable by governance
     */
    struct StakeConfig {
        uint256 minStakeAmount;     // Minimum stake to initiate dispute (renamed from minDisputeStake for consistency)
        uint256 minAppealStake;     // Minimum stake to appeal ruling
        address stakeToken;         // Token used for staking (0x0 for ETH)
        uint16 protocolFeeBps;      // Protocol fee on dispute resolution
        uint16 rewardBps;           // Reward for valid dispute (basis points of loser stake)
        uint16 slashBps;            // Slash for invalid dispute (basis points)
        uint40 responsePeriod;      // Time for content owner to respond
        uint40 evidencePeriod;      // Time for evidence submission
        uint40 appealPeriod;        // Time window for appeals
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                       ACCOUNT ABSTRACTION STRUCTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Enterprise subscription for gasless transactions
     * @dev Used by AxiomPaymaster for ERC-4337 sponsorship
     */
    struct Subscription {
        address enterprise;         // 20 bytes - Enterprise account
        SubscriptionTier tier;      // 1 byte - Subscription level
        uint256 remainingCredits;   // 32 bytes - Remaining sponsored actions
        uint256 totalSpent;         // 32 bytes - Cumulative ETH spent by paymaster
        uint40 activatedAt;         // 5 bytes - Subscription start
        uint40 expiresAt;           // 5 bytes - Subscription expiry
        uint256 maxGasPerOp;        // 32 bytes - Max gas paymaster will cover per op
    }

    /**
     * @notice Session key configuration for smart accounts
     * @dev Allows limited delegated signing without exposing main key
     */
    struct SessionKey {
        address key;                // 20 bytes - Session key address
        address target;             // 20 bytes - Allowed target contract
        bytes4[] allowedSelectors;  // Array of allowed function selectors
        uint48 validAfter;          // 6 bytes - Session start
        uint48 validUntil;          // 6 bytes - Session expiry
        uint256 spendingLimit;      // 32 bytes - Max value per transaction
        bool active;                // 1 byte - Whether session is active
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          PRIVACY (ZK) STRUCTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Private content registration record
     * @dev Uses ZK-SNARKs to prove ownership without revealing address
     */
    struct PrivateRecord {
        bytes32 contentHash;        // 32 bytes - Hash of content
        bytes32 commitment;         // 32 bytes - ZK commitment to identity
        bytes32 nullifierHash;      // 32 bytes - Prevents double-registration
        uint40 timestamp;           // 5 bytes - Registration timestamp
        ContentStatus status;       // 1 byte - Current status
        bool metadataDeleted;       // 1 byte - True if GDPR erasure requested
        string metadataURI;         // Dynamic - Off-chain metadata (can be deleted)
    }

    /**
     * @notice GDPR compliance request
     * @dev Tracks data subject requests for audit compliance
     */
    enum GDPRRequestType {
        ACCESS,         // 0 - Right to access personal data
        RECTIFICATION,  // 1 - Right to correct inaccurate data
        ERASURE,        // 2 - Right to be forgotten
        PORTABILITY,    // 3 - Right to data portability
        OBJECTION       // 4 - Right to object to processing
    }

    struct GDPRRequest {
        bytes32 recordId;           // 32 bytes - Related content record
        bytes32 requestId;          // 32 bytes - Unique request ID
        GDPRRequestType requestType; // 1 byte - Type of GDPR request
        uint40 requestedAt;         // 5 bytes - Request timestamp
        uint40 processedAt;         // 5 bytes - Completion timestamp (0 if pending)
        bool processed;             // 1 byte - Whether request was fulfilled
        bytes32 proofOfCompliance;  // 32 bytes - Hash of compliance evidence
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                               EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    // ─────────────────────────── Content Events ───────────────────────────────

    /**
     * @notice Emitted when new content is registered
     */
    event ContentRegistered(
        bytes32 indexed recordId,
        address indexed issuer,
        bytes32 contentHash,
        bytes32 manifestHash,
        uint40 timestamp,
        string metadataURI
    );

    /**
     * @notice Emitted when content is revoked
     */
    event ContentRevoked(
        bytes32 indexed recordId,
        address indexed issuer,
        string reason
    );

    /**
     * @notice Emitted when content status changes to disputed
     */
    event ContentDisputed(
        bytes32 indexed recordId,
        bytes32 indexed disputeId,
        address indexed challenger,
        DisputeReason reason
    );

    // ─────────────────────────── DID Events ───────────────────────────────────

    /**
     * @notice Emitted when DID is registered (ERC-1056 compatible)
     */
    event DIDRegistered(
        address indexed identity,
        string did,
        bytes32 didDocumentHash
    );

    /**
     * @notice Emitted when DID attribute changes (ERC-1056 standard)
     */
    event DIDAttributeChanged(
        address indexed identity,
        bytes32 indexed name,
        bytes value,
        uint256 validTo,
        uint256 previousChange
    );

    /**
     * @notice Emitted when delegate is added/changed (ERC-1056 standard)
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
     */
    event VerificationLevelChanged(
        address indexed identity,
        VerificationLevel oldLevel,
        VerificationLevel newLevel,
        address indexed verifier
    );

    // ─────────────────────────── License Events ───────────────────────────────

    /**
     * @notice Emitted when license is created
     */
    event LicenseCreated(
        uint256 indexed licenseId,
        bytes32 indexed recordId,
        address indexed licensor,
        LicenseType licenseType,
        uint256 price
    );

    /**
     * @notice Emitted when license is purchased
     */
    event LicensePurchased(
        uint256 indexed licenseId,
        uint256 indexed tokenId,
        address indexed licensee,
        uint256 pricePaid
    );

    /**
     * @notice Emitted when royalty is distributed
     */
    event RoyaltyDistributed(
        bytes32 indexed recordId,
        address indexed recipient,
        uint256 amount
    );

    // ─────────────────────────── Dispute Events ───────────────────────────────

    /**
     * @notice Emitted when dispute is initiated
     */
    event DisputeInitiated(
        bytes32 indexed disputeId,
        bytes32 indexed recordId,
        address indexed challenger,
        DisputeReason reason,
        uint256 stakeAmount
    );

    /**
     * @notice Emitted when dispute is resolved
     */
    event DisputeResolved(
        bytes32 indexed disputeId,
        DisputeStatus outcome,
        address winner
    );

    /**
     * @notice Emitted when dispute is escalated to external arbitrator
     */
    event DisputeEscalated(
        bytes32 indexed disputeId,
        address indexed arbitrator,
        bytes32 externalDisputeId
    );

    // ─────────────────────────── Privacy Events ───────────────────────────────

    /**
     * @notice Emitted when private content is registered
     */
    event PrivateContentRegistered(
        bytes32 indexed recordId,
        bytes32 indexed commitment,
        bytes32 nullifierHash,
        uint40 timestamp
    );

    /**
     * @notice Emitted when GDPR erasure is processed
     */
    event GDPRErasureProcessed(
        bytes32 indexed recordId,
        bytes32 indexed requestId,
        uint40 processedAt
    );

    // ─────────────────────────── Treasury Events ───────────────────────────────

    /**
     * @notice Emitted when fee is collected
     */
    event FeeCollected(
        address indexed payer,
        uint256 amount,
        bytes32 indexed recordId
    );

    /**
     * @notice Emitted when subscription is activated
     */
    event SubscriptionActivated(
        address indexed enterprise,
        SubscriptionTier tier,
        uint256 credits,
        uint40 expiresAt
    );

    // ═══════════════════════════════════════════════════════════════════════════
    //                               ERRORS
    // ═══════════════════════════════════════════════════════════════════════════

    // ─────────────────────────── Content Errors ───────────────────────────────

    /// @notice Thrown when content hash already exists
    error ContentAlreadyExists(bytes32 recordId);

    /// @notice Thrown when content is not found
    error ContentNotFound(bytes32 recordId);

    /// @notice Thrown when caller is not the issuer
    error NotIssuer(address caller, address issuer);

    /// @notice Thrown when content is already revoked
    error ContentAlreadyRevoked(bytes32 recordId);

    /// @notice Thrown when content status doesn't allow operation
    error InvalidContentStatus(bytes32 recordId, ContentStatus status);

    // ─────────────────────────── Fee Errors ───────────────────────────────────

    /// @notice Thrown when insufficient fee is sent
    error InsufficientFee(uint256 sent, uint256 required);

    /// @notice Thrown when rate limit is exceeded
    error RateLimitExceeded(address user);

    /// @notice Thrown when address is banned
    error AddressBanned(address user);

    // ─────────────────────────── Identity Errors ──────────────────────────────

    /// @notice Thrown when DID already exists for address
    error DIDAlreadyExists(address user);

    /// @notice Thrown when DID not found
    error DIDNotFound(address user);

    /// @notice Thrown when DID is expired
    error DIDExpired(address user, uint40 expiredAt);

    /// @notice Thrown when DID is revoked
    error DIDRevoked(address user);

    /// @notice Thrown when delegate is not authorized
    error UnauthorizedDelegate(address identity, address delegate);

    // ─────────────────────────── License Errors ───────────────────────────────

    /// @notice Thrown when license not found
    error LicenseNotFound(uint256 licenseId);

    /// @notice Thrown when license is expired
    error LicenseExpired(uint256 licenseId, uint40 expiredAt);

    /// @notice Thrown when license is already purchased (exclusive)
    error LicenseAlreadyPurchased(uint256 licenseId);

    /// @notice Thrown when caller is not licensor
    error NotLicensor(address caller, address licensor);

    /// @notice Thrown when royalty shares don't sum to 10000
    error InvalidRoyaltySplit(uint256 totalShares);

    // ─────────────────────────── Dispute Errors ───────────────────────────────

    /// @notice Thrown when dispute not found
    error DisputeNotFound(bytes32 disputeId);

    /// @notice Thrown when stake is insufficient
    error InsufficientStake(uint256 provided, uint256 required);

    /// @notice Thrown when dispute deadline passed
    error DisputeDeadlinePassed(bytes32 disputeId, uint40 deadline);

    /// @notice Thrown when dispute is not in expected status
    error InvalidDisputeStatus(bytes32 disputeId, DisputeStatus expected, DisputeStatus actual);

    /// @notice Thrown when caller cannot perform dispute action
    error UnauthorizedDisputeAction(bytes32 disputeId, address caller);

    // ─────────────────────────── Privacy Errors ───────────────────────────────

    /// @notice Thrown when ZK proof is invalid
    error InvalidZKProof();

    /// @notice Thrown when nullifier has been used (double-registration)
    error NullifierAlreadyUsed(bytes32 nullifierHash);

    /// @notice Thrown when GDPR request is invalid
    error InvalidGDPRRequest(bytes32 requestId);

    // ─────────────────────────── General Errors ───────────────────────────────

    /// @notice Thrown when arrays have mismatched lengths
    error ArrayLengthMismatch();

    /// @notice Thrown when batch size exceeds limit
    error BatchSizeExceeded(uint256 size, uint256 maxSize);

    /// @notice Thrown when zero address is provided
    error ZeroAddress();

    /// @notice Thrown when operation is not permitted
    error OperationNotPermitted();
}
