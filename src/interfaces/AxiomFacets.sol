// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypes} from "../libraries/AxiomTypes.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";

/**
 * @title AxiomFacets
 * @notice Helper interface aggregating all facet functions for testing Diamond proxy
 * @dev This interface should only be used in tests to make casting easier.
 *      In production, the Diamond proxy routes calls to the appropriate facets.
 */
interface AxiomFacets {
    // ============ AxiomRegistry Functions ============
    function register(bytes32 _contentHash, string calldata _metadataURI) external payable returns (bytes32);
    function batchRegister(bytes32[] calldata _contentHashes, string[] calldata _metadataURIs) external payable returns (bytes32[] memory);
    function revoke(bytes32 _recordId, string calldata _reason) external;
    function verify(bytes32 _contentHash, address _claimedIssuer) external view returns (bool, AxiomTypes.AxiomRecord memory);
    function getRecord(bytes32 _recordId) external view returns (AxiomTypes.AxiomRecord memory);
    function getRecordsByIssuer(address _issuer) external view returns (bytes32[] memory);
    function getTotalRecords() external view returns (uint256);
    
    // ============ AxiomTreasury Functions ============
    function setBaseFee(uint256 _fee) external;
    function setEnterpriseRate(address _user, uint256 _rate) external;
    function grantEnterpriseStatus(address _user) external;
    function revokeEnterpriseStatus(address _user) external;
    function withdraw(address _to, uint256 _amount) external;
    function setTreasuryWallet(address _wallet) external;
    function getFee(address _user) external view returns (uint256);
    function getBaseFee() external view returns (uint256);
    function getTotalFeesCollected() external view returns (uint256);
    function isEnterpriseUser(address _user) external view returns (bool);
    
    // ============ AxiomIdentity Functions ============
    function registerIdentity(string calldata _name, string calldata _proofURI) external;
    function updateIdentity(string calldata _name, string calldata _proofURI) external;
    function verifyIdentity(address _user) external;
    function revokeVerification(address _user) external;
    function resolveIdentity(address _user) external view returns (AxiomTypes.IdentityInfo memory);
    function resolveByName(string calldata _name) external view returns (address);
    function isIdentityVerified(address _user) external view returns (bool);
    
    // ============ AxiomAccess Functions ============
    function banAddress(address _user, string calldata _reason) external;
    function unbanAddress(address _user) external;
    function isBanned(address _user) external view returns (bool);
    function disputeContent(bytes32 _recordId, string calldata _reason) external;
    function setRateLimit(uint256 _window, uint256 _maxActions) external;
    function setMaxBatchSize(uint256 _size) external;
    
    // ============ AxiomLicenseFacet Functions (ERC-721 + Licensing) ============
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
    ) external returns (uint256);
    function updateLicense(uint256 _licenseId, uint256 _price, uint40 _validUntil, bool _exclusive) external;
    function deactivateLicense(uint256 _licenseId) external;
    function purchaseLicense(uint256 _licenseId, uint40 _duration) external payable returns (uint256);
    function purchaseLicenseFor(uint256 _licenseId, address _recipient, uint40 _duration) external payable returns (uint256);
    
    // ERC-721 Functions
    function balanceOf(address owner) external view returns (uint256);
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
    function setApprovalForAll(address operator, bool approved) external;
    function getApproved(uint256 tokenId) external view returns (address);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
    function name() external pure returns (string memory);
    function symbol() external pure returns (string memory);
    function tokenURI(uint256 tokenId) external view returns (string memory);
    
    // ERC-2981 + Royalty Functions
    function royaltyInfo(uint256 tokenId, uint256 salePrice) external view returns (address, uint256);
    function setRoyaltySplit(bytes32 _recordId, address[] calldata _recipients, uint16[] calldata _shares) external;
    
    // ============ AxiomDisputeFacet Functions ============
    function initiateDispute(
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI
    ) external payable returns (bytes32);
    function initiateDisputeWithToken(
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI,
        address _stakeToken,
        uint256 _stakeAmount
    ) external returns (bytes32);
    function respondToDispute(bytes32 _disputeId, string calldata _responseURI) external;
    function submitEvidence(bytes32 _disputeId, string calldata _evidenceURI) external;
    function escalateToArbitration(bytes32 _disputeId, address _arbitrator) external payable;
    function resolveByTimeout(bytes32 _disputeId) external;
    function claimStake(bytes32 _disputeId) external returns (uint256);
    function getDispute(bytes32 _disputeId) external view returns (AxiomTypesV2.Dispute memory);
    function getDisputesByRecord(bytes32 _recordId) external view returns (bytes32[] memory);
    function hasActiveDispute(bytes32 _recordId) external view returns (bool);
    
    // ============ AxiomDIDRegistry Functions ============
    function registerDID(
        string calldata _did,
        bytes32 _didDocumentHash,
        string calldata _publicKeyJwk
    ) external;
    function updateDIDDocument(bytes32 _newDocumentHash) external;
    function setServiceEndpoint(string calldata _serviceEndpoint) external;
    function revokeDID() external;
    function addDelegate(address _delegate, bytes32 _delegateType, uint256 _validity) external;
    function revokeDelegate(address _delegate, bytes32 _delegateType) external;
    function validDelegate(address _identity, bytes32 _delegateType, address _delegate) external view returns (bool);
    function getDelegates(address _identity) external view returns (AxiomTypesV2.DIDDelegate[] memory);
    function setVerificationLevel(address _user, AxiomTypesV2.VerificationLevel _level) external;
    function getVerificationLevel(address _user) external view returns (AxiomTypesV2.VerificationLevel);
    function meetsVerificationLevel(address _user, AxiomTypesV2.VerificationLevel _minLevel) external view returns (bool);
    function resolveDID(string calldata _did) external view returns (AxiomTypesV2.DIDIdentity memory);
    function getIdentity(address _user) external view returns (AxiomTypesV2.DIDIdentity memory);
    function hasDID(address _user) external view returns (bool);
    function isDIDActive(address _user) external view returns (bool);
    function getDIDString(address _user) external view returns (string memory);
    function setAttribute(bytes32 _name, bytes calldata _value, uint256 _validity) external;
    function revokeAttribute(bytes32 _name, bytes calldata _value) external;
    function verifySignature(address _identity, bytes32 _hash, bytes calldata _signature) external view returns (bool, address);
    function nonce(address _identity) external view returns (uint256);

    // ============ AxiomPrivacyFacet Functions ============
    function privateRegister(
        bytes32 _contentHash,
        bytes32 _commitment,
        bytes32 _nullifierHash,
        bytes calldata _zkProof,
        string calldata _metadataURI
    ) external payable returns (bytes32);
    function verifyOwnership(
        bytes32 _recordId,
        bytes32 _commitment,
        bytes calldata _zkProof
    ) external view returns (bool);
    function requestErasure(bytes32 _recordId, bytes calldata _ownershipProof) external returns (bytes32);
    function confirmErasure(bytes32 _requestId, bytes32 _proofOfCompliance) external;
    function getPrivateRecord(bytes32 _recordId) external view returns (AxiomTypesV2.PrivateRecord memory);
    function contentExists(bytes32 _contentHash) external view returns (bool);
    function nullifierUsed(bytes32 _nullifierHash) external view returns (bool);
    function isMetadataDeleted(bytes32 _recordId) external view returns (bool);
    function getGDPRRequest(bytes32 _requestId) external view returns (AxiomTypesV2.GDPRRequest memory);
    function getRecordsByCommitment(bytes32 _commitment) external view returns (bytes32[] memory);
}
