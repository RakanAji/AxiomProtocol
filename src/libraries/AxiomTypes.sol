// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AxiomTypes
 * @author Axiom Protocol Team
 * @notice Core data structures and enums for the Axiom Protocol
 * @dev All structs are gas-optimized using tight variable packing
 */
library AxiomTypes {
    // ============ Enums ============

    /**
     * @notice Status of registered content
     * @dev Uses uint8 for gas optimization
     */
    enum ContentStatus {
        ACTIVE,    // 0 - Content is valid and verified
        REVOKED,   // 1 - Content was revoked by issuer
        DISPUTED   // 2 - Content is under dispute (flagged by operator)
    }

    /**
     * @notice Supported hash algorithms for future-proofing
     * @dev Currently only SHA256 is used, but designed for extensibility
     */
    enum HashAlgorithm {
        SHA256,     // 0 - Default algorithm
        SHA3_256,   // 1 - Future support
        KECCAK256   // 2 - Native Ethereum hash
    }

    // ============ Structs ============

    /**
     * @notice Core record for registered content
     * @dev Packed for gas optimization:
     *      - Slot 1: issuer (20 bytes) + timestamp (5 bytes) + status (1 byte) + algorithm (1 byte) = 27 bytes
     *      - Slot 2: contentHash (32 bytes)
     *      - Slot 3+: metadataURI (dynamic string)
     */
    struct AxiomRecord {
        address issuer;         // 20 bytes - Wallet address that signed the content
        uint40 timestamp;       // 5 bytes - Block timestamp (enough until year 36,812)
        ContentStatus status;   // 1 byte - Current status of the record
        HashAlgorithm algorithm; // 1 byte - Hash algorithm used
        bytes32 contentHash;    // 32 bytes - Hash of the content
        string metadataURI;     // Dynamic - IPFS/Arweave link to metadata JSON
    }

    /**
     * @notice Identity information for registered users
     * @dev Used for DID resolution
     */
    struct IdentityInfo {
        string name;            // Display name (e.g., "Reuters News")
        string proofURI;        // Link to identity proof document
        bool isVerified;        // Whether identity has been verified by operator
        uint40 registeredAt;    // When identity was registered
    }

    /**
     * @notice Metadata structure for content (stored off-chain on IPFS)
     * @dev This struct is for documentation, actual data stored as JSON
     */
    struct ContentMetadata {
        string title;           // Title of the content
        string description;     // Description of the content
        string contentType;     // MIME type (e.g., "image/jpeg", "application/pdf")
        string[] tags;          // Searchable tags
        uint256 fileSize;       // Size in bytes
        string originalFilename; // Original filename
    }

    // ============ Events ============

    /**
     * @notice Emitted when new content is registered
     */
    event ContentRegistered(
        bytes32 indexed recordId,
        address indexed issuer,
        bytes32 contentHash,
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
        address indexed operator,
        string reason
    );

    /**
     * @notice Emitted when identity is registered
     */
    event IdentityRegistered(
        address indexed user,
        string name,
        string proofURI
    );

    /**
     * @notice Emitted when identity is verified by operator
     */
    event IdentityVerified(
        address indexed user,
        address indexed verifier
    );

    /**
     * @notice Emitted when fee is collected
     */
    event FeeCollected(
        address indexed payer,
        uint256 amount,
        bytes32 indexed recordId
    );

    // ============ Errors ============

    /// @notice Thrown when content hash already exists
    error ContentAlreadyExists(bytes32 recordId);

    /// @notice Thrown when content is not found
    error ContentNotFound(bytes32 recordId);

    /// @notice Thrown when caller is not the issuer
    error NotIssuer(address caller, address issuer);

    /// @notice Thrown when content is already revoked
    error ContentAlreadyRevoked(bytes32 recordId);

    /// @notice Thrown when insufficient fee is sent
    error InsufficientFee(uint256 sent, uint256 required);

    /// @notice Thrown when rate limit is exceeded
    error RateLimitExceeded(address user);

    /// @notice Thrown when address is banned
    error AddressBanned(address user);

    /// @notice Thrown when identity already exists
    error IdentityAlreadyExists(address user);

    /// @notice Thrown when identity not found
    error IdentityNotFound(address user);

    /// @notice Thrown when arrays have mismatched lengths
    error ArrayLengthMismatch();

    /// @notice Thrown when batch size exceeds limit
    error BatchSizeExceeded(uint256 size, uint256 maxSize);
}
