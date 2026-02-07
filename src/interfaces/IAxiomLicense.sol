// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";

/**
 * @title IAxiomLicense
 * @author Axiom Protocol Team
 * @notice Interface for Programmable IP License management
 * @dev Implements ERC-721 compatible license NFTs with ERC-2981 royalty support
 *      
 *      This interface enables:
 *      - Creation of license templates attached to registered content
 *      - Purchase of licenses (minted as transferable NFTs)
 *      - Royalty distribution following ERC-2981 standard
 *      - Sublicensing for revenue sharing
 *      - Geographic and temporal restrictions
 *
 *      Reference Standards:
 *      - ERC-721: https://eips.ethereum.org/EIPS/eip-721
 *      - ERC-2981: https://eips.ethereum.org/EIPS/eip-2981
 *      - Creative Commons: https://creativecommons.org/licenses/
 */
interface IAxiomLicense {
    // ═══════════════════════════════════════════════════════════════════════════
    //                          LICENSE CREATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Create a new license template for registered content
     * @dev Only the content issuer (or authorized delegate) can create licenses
     *      Multiple license types can exist for the same content (e.g., personal & commercial)
     *
     *      Requirements:
     *      - Caller must be the content issuer or authorized delegate
     *      - Content must exist and be ACTIVE
     *      - Price must be >= 0 (free licenses allowed)
     *      - Royalty basis points must be <= 10000 (100%)
     *
     *      Emits {LicenseCreated} event
     *
     * @param _recordId The content record ID this license applies to
     * @param _licenseType Type of license (CC-BY, Commercial, etc.)
     * @param _price Price in payment token (or ETH if paymentToken is 0x0)
     * @param _paymentToken ERC-20 token for payment (0x0 for ETH)
     * @param _royaltyBps Royalty percentage in basis points (250 = 2.5%)
     * @param _validUntil License expiration timestamp (0 for perpetual)
     * @param _exclusive If true, only one licensee allowed
     * @param _sublicensable If true, licensee can create sublicenses
     * @param _customTermsURI IPFS URI to full license terms (required for CUSTOM type)
     * @return licenseId Unique identifier for the created license
     */
    function createLicense(
        bytes32 _recordId,
        AxiomTypesV2.LicenseType _licenseType,
        uint256 _price,
        address _paymentToken,
        uint16 _royaltyBps,
        uint40 _validUntil,
        bool _exclusive,
        bool _sublicensable,
        string calldata _customTermsURI
    ) external returns (uint256 licenseId);

    /**
     * @notice Update license terms (before any purchases)
     * @dev Can only be updated if no licenses have been sold
     *
     *      Requirements:
     *      - Caller must be the licensor
     *      - License must have no purchases yet
     *
     * @param _licenseId License ID to update
     * @param _price New price
     * @param _validUntil New expiration
     * @param _exclusive New exclusivity setting
     */
    function updateLicense(
        uint256 _licenseId,
        uint256 _price,
        uint40 _validUntil,
        bool _exclusive
    ) external;

    /**
     * @notice Deactivate a license (no new purchases allowed)
     * @dev Existing purchases remain valid until their expiration
     *
     *      Requirements:
     *      - Caller must be the licensor
     *
     * @param _licenseId License ID to deactivate
     */
    function deactivateLicense(uint256 _licenseId) external;

    // ═══════════════════════════════════════════════════════════════════════════
    //                          LICENSE PURCHASE
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Purchase a license (mints License NFT to buyer)
     * @dev Payment is distributed according to royalty split configuration
     *      
     *      For ETH payment: send value with transaction
     *      For ERC-20 payment: approve tokens first, then call
     *
     *      Requirements:
     *      - License must be active
     *      - If exclusive, no existing licensee
     *      - Correct payment amount
     *
     *      Emits {LicensePurchased} event
     *      Emits ERC-721 {Transfer} event
     *
     * @param _licenseId License template ID to purchase
     * @param _duration Requested license duration in seconds (for time-limited licenses)
     * @return tokenId The minted NFT token ID representing the license
     */
    function purchaseLicense(
        uint256 _licenseId,
        uint40 _duration
    ) external payable returns (uint256 tokenId);

    /**
     * @notice Purchase license on behalf of another address (gift)
     * @dev Same as purchaseLicense but mints to specified recipient
     *
     * @param _licenseId License template ID
     * @param _recipient Address to receive the license NFT
     * @param _duration Requested license duration
     * @return tokenId The minted NFT token ID
     */
    function purchaseLicenseFor(
        uint256 _licenseId,
        address _recipient,
        uint40 _duration
    ) external payable returns (uint256 tokenId);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          SUBLICENSING
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Create a sublicense from an existing license (if permitted)
     * @dev Sublicense revenue is split with original licensor according to config
     *
     *      Requirements:
     *      - Caller must own the parent license NFT
     *      - Parent license must be sublicensable
     *      - Parent license must still be valid
     *
     *      Emits {SublicenseCreated} event
     *
     * @param _parentTokenId Token ID of the license being sublicensed
     * @param _price Price for the sublicense
     * @param _validUntil Sublicense expiration (cannot exceed parent)
     * @return sublicenseId New sublicense ID
     */
    function createSublicense(
        uint256 _parentTokenId,
        uint256 _price,
        uint40 _validUntil
    ) external returns (uint256 sublicenseId);

    /**
     * @notice Purchase a sublicense
     * @dev Revenue split: original creator gets primary share, sublicensor gets secondary
     *
     * @param _sublicenseId Sublicense ID to purchase
     * @return tokenId Minted sublicense NFT token ID
     */
    function purchaseSublicense(uint256 _sublicenseId) 
        external payable returns (uint256 tokenId);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ROYALTY MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Set royalty distribution split for content
     * @dev All secondary sales of licenses will use this split
     *      Shares must sum to 10000 (100%)
     *
     *      Requirements:
     *      - Caller must be the content issuer
     *      - Recipients and shares arrays must have same length
     *      - Shares must sum to 10000
     *
     * @param _recordId Content record ID
     * @param _recipients Array of royalty recipient addresses
     * @param _shares Array of share amounts in basis points
     */
    function setRoyaltySplit(
        bytes32 _recordId,
        address[] calldata _recipients,
        uint16[] calldata _shares
    ) external;

    /**
     * @notice Claim accumulated royalties for caller
     * @dev Transfers all pending royalties to the caller
     *
     * @param _recordId Content record ID to claim royalties for
     * @return amount Total amount claimed
     */
    function claimRoyalties(bytes32 _recordId) external returns (uint256 amount);

    /**
     * @notice Claim royalties in a specific token
     * @param _recordId Content record ID
     * @param _token ERC-20 token address (0x0 for ETH)
     * @return amount Amount claimed
     */
    function claimRoyaltiesToken(bytes32 _recordId, address _token) 
        external returns (uint256 amount);

    /**
     * @notice Get pending royalties for an address
     * @param _recipient Address to check
     * @param _recordId Content record ID
     * @return pending Amount of pending royalties
     */
    function pendingRoyalties(address _recipient, bytes32 _recordId) 
        external view returns (uint256 pending);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ERC-2981 ROYALTY INFO
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Returns royalty payment information for secondary sales
     * @dev ERC-2981 standard implementation
     *      Marketplaces call this to determine royalty payments
     *
     * @param _tokenId License NFT token ID
     * @param _salePrice Sale price of the NFT
     * @return receiver Address to receive royalty payment
     * @return royaltyAmount Amount of royalty to pay
     */
    function royaltyInfo(uint256 _tokenId, uint256 _salePrice)
        external view returns (address receiver, uint256 royaltyAmount);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          LICENSE QUERIES
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get license template information
     * @param _licenseId License template ID
     * @return license Full License struct
     */
    function getLicense(uint256 _licenseId) 
        external view returns (AxiomTypesV2.License memory license);

    /**
     * @notice Get all licenses for a content record
     * @param _recordId Content record ID
     * @return licenseIds Array of license IDs
     */
    function getLicensesByRecord(bytes32 _recordId) 
        external view returns (uint256[] memory licenseIds);

    /**
     * @notice Get all licenses owned by an address
     * @param _owner Address to query
     * @return tokenIds Array of owned license NFT token IDs
     */
    function getLicensesByOwner(address _owner) 
        external view returns (uint256[] memory tokenIds);

    /**
     * @notice Check if an address has a valid license for content
     * @dev Used to gate access to licensed content
     *
     * @param _licensee Address to check
     * @param _recordId Content record ID
     * @return isValid Whether licensee has valid (non-expired) license
     * @return licenseType The type of license held
     */
    function hasValidLicense(address _licensee, bytes32 _recordId) 
        external view returns (bool isValid, AxiomTypesV2.LicenseType licenseType);

    /**
     * @notice Check if a specific license NFT is still valid
     * @param _tokenId License NFT token ID
     * @return isValid Whether license is valid (active and not expired)
     */
    function isLicenseValid(uint256 _tokenId) external view returns (bool isValid);

    /**
     * @notice Get royalty split configuration for content
     * @param _recordId Content record ID
     * @return split RoyaltySplit struct with recipients and shares
     */
    function getRoyaltySplit(bytes32 _recordId) 
        external view returns (AxiomTypesV2.RoyaltySplit memory split);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          TERRITORY MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Set geographic restrictions for a license
     * @dev Restrictions are stored as JSON on IPFS, hash stored on-chain
     *
     *      JSON format:
     *      {
     *        "allowed": ["US", "EU", "JP"],
     *        "excluded": ["CN", "RU"],
     *        "global": false
     *      }
     *
     * @param _licenseId License ID to update
     * @param _restrictionsURI IPFS URI to restrictions JSON
     */
    function setTerritoryRestrictions(
        uint256 _licenseId,
        string calldata _restrictionsURI
    ) external;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Emitted when a license template is created
     * @param licenseId Unique license ID
     * @param recordId Associated content record ID
     * @param licensor Address of the content owner
     * @param licenseType Type of license
     * @param price License price
     */
    event LicenseCreated(
        uint256 indexed licenseId,
        bytes32 indexed recordId,
        address indexed licensor,
        AxiomTypesV2.LicenseType licenseType,
        uint256 price
    );

    /**
     * @notice Emitted when a license is purchased
     * @param licenseId License template ID
     * @param tokenId Minted NFT token ID
     * @param licensee Buyer address
     * @param pricePaid Amount paid
     */
    event LicensePurchased(
        uint256 indexed licenseId,
        uint256 indexed tokenId,
        address indexed licensee,
        uint256 pricePaid
    );

    /**
     * @notice Emitted when a sublicense is created
     * @param sublicenseId New sublicense ID
     * @param parentTokenId Parent license NFT token ID
     * @param sublicensor Address creating the sublicense
     */
    event SublicenseCreated(
        uint256 indexed sublicenseId,
        uint256 indexed parentTokenId,
        address indexed sublicensor
    );

    /**
     * @notice Emitted when royalties are distributed
     * @param recordId Content record ID
     * @param recipient Royalty recipient
     * @param amount Amount distributed
     * @param token Payment token (0x0 for ETH)
     */
    event RoyaltyDistributed(
        bytes32 indexed recordId,
        address indexed recipient,
        uint256 amount,
        address token
    );

    /**
     * @notice Emitted when royalty split is updated
     * @param recordId Content record ID
     * @param recipients Array of recipient addresses
     * @param shares Array of share amounts
     */
    event RoyaltySplitUpdated(
        bytes32 indexed recordId,
        address[] recipients,
        uint16[] shares
    );

    /**
     * @notice Emitted when license is deactivated
     * @param licenseId License ID
     * @param licensor Address that deactivated
     */
    event LicenseDeactivated(
        uint256 indexed licenseId,
        address indexed licensor
    );
}
