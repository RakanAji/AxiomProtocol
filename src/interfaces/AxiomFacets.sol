// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypes} from "../libraries/AxiomTypes.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";

/**
 * @title AxiomFacets
 * @notice Canonical aggregate ABI for the public APIs routed through AxiomRouter.
 * @dev Router-native functions and deliberately unrouted legacy/roadmap methods
 *      are excluded. AxiomRouter uses custom selector dispatch rather than the
 *      standard EIP-2535 Diamond cut and loupe interfaces.
 */
interface AxiomFacets {
    // ============ AxiomRegistry Functions ============
    function register(bytes32 _contentHash, string calldata _metadataURI) external payable returns (bytes32);
    function batchRegister(bytes32[] calldata _contentHashes, string[] calldata _metadataURIs)
        external
        payable
        returns (bytes32[] memory);
    function revoke(bytes32 _recordId, string calldata _reason) external;
    function verify(bytes32 _contentHash, address _claimedIssuer)
        external
        view
        returns (bool, AxiomTypes.AxiomRecord memory);
    function getRecord(bytes32 _recordId) external view returns (AxiomTypes.AxiomRecord memory);
    function getRecordsByIssuer(address _issuer) external view returns (bytes32[] memory);
    function getTotalRecords() external view returns (uint256);
    function getRecordIds(uint256 _offset, uint256 _limit) external view returns (bytes32[] memory);

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
    function setRateLimit(uint256 _window, uint256 _maxActions) external;
    function setMaxBatchSize(uint256 _size) external;
    function isPaused() external view returns (bool);
    function getRateLimitSettings() external view returns (uint256 window, uint256 maxActions);
    function getMaxBatchSize() external view returns (uint256);

    // ============ AxiomLicenseFacet Functions (ERC-721 + Licensing) ============
    function setLicenseTreasury(address _treasury) external;
    function getLicenseTreasury() external view returns (address);
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
    function purchaseLicenseFor(uint256 _licenseId, address _recipient, uint40 _duration)
        external
        payable
        returns (uint256);

    // ERC-721 Functions
    function balanceOf(address owner) external view returns (uint256);
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;
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

    // License Query Functions
    function getLicense(uint256 _licenseId) external view returns (AxiomTypesV2.License memory);
    function getLicensesByRecord(bytes32 _recordId) external view returns (uint256[] memory);
    function isLicenseValid(uint256 _tokenId) external view returns (bool);
    function getRoyaltySplit(bytes32 _recordId) external view returns (AxiomTypesV2.RoyaltySplit memory);

    // ============ AxiomDisputeFacet Functions ============
    function configureStakeConfig(AxiomTypesV2.StakeConfig calldata _config) external;
    function setArbitrator(address _arbitrator, bool _approved) external;
    function initiateDispute(bytes32 _recordId, AxiomTypesV2.DisputeReason _reason, string calldata _evidenceURI)
        external
        payable
        returns (bytes32);
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
    function settleDispute(
        bytes32 _disputeId,
        uint16 _challengerShare,
        bytes calldata _ownerSig,
        bytes calldata _challengerSig
    ) external;
    function settlementDigest(bytes32 _disputeId, uint16 _challengerShare) external view returns (bytes32);
    function claimStake(bytes32 _disputeId) external returns (uint256);
    function getDispute(bytes32 _disputeId) external view returns (AxiomTypesV2.Dispute memory);
    function getDisputesByRecord(bytes32 _recordId) external view returns (bytes32[] memory);
    function getDisputesByChallenger(address _challenger) external view returns (bytes32[] memory);
    function getActiveDisputes(uint256 _offset, uint256 _limit) external view returns (bytes32[] memory);
    function hasActiveDispute(bytes32 _recordId) external view returns (bool);
    function getStakeConfig() external view returns (AxiomTypesV2.StakeConfig memory);
    function getMinimumStake(bytes32 _recordId) external view returns (uint256);
    function getApprovedArbitrators() external view returns (address[] memory);
    function isArbitratorApproved(address _arbitrator) external view returns (bool);
    function appeal(bytes32 _disputeId, string calldata _reason) external payable returns (bytes32);
    function getAppealDeadline(bytes32 _disputeId) external view returns (uint256);
    function rule(uint256 _externalDisputeId, uint256 _ruling) external;
    function getArbitratorFee(address _arbitrator, AxiomTypesV2.DisputeReason _reason) external view returns (uint256);

    // License additional query functions
    function hasValidLicense(address _licensee, bytes32 _recordId)
        external
        view
        returns (bool, AxiomTypesV2.LicenseType);
    function setTerritoryRestrictions(uint256 _licenseId, string calldata _restrictionsURI) external;
    function getLicensesByOwner(address _owner) external view returns (uint256[] memory);

    // ============ AxiomDIDRegistry Functions ============
    function registerDID(string calldata _did, bytes32 _didDocumentHash, string calldata _publicKeyJwk) external;
    function updateDIDDocument(bytes32 _newDocumentHash) external;
    function setServiceEndpoint(string calldata _serviceEndpoint) external;
    function revokeDID() external;
    function addDelegate(address _delegate, bytes32 _delegateType, uint256 _validity) external;
    function revokeDelegate(address _delegate, bytes32 _delegateType) external;
    function validDelegate(address _identity, bytes32 _delegateType, address _delegate) external view returns (bool);
    function getDelegates(address _identity) external view returns (AxiomTypesV2.DIDDelegate[] memory);
    function setVerificationLevel(address _user, AxiomTypesV2.VerificationLevel _level) external;
    function getVerificationLevel(address _user) external view returns (AxiomTypesV2.VerificationLevel);
    function meetsVerificationLevel(address _user, AxiomTypesV2.VerificationLevel _minLevel)
        external
        view
        returns (bool);
    function resolveDID(string calldata _did) external view returns (AxiomTypesV2.DIDIdentity memory);
    function getIdentity(address _user) external view returns (AxiomTypesV2.DIDIdentity memory);
    function hasDID(address _user) external view returns (bool);
    function isDIDActive(address _user) external view returns (bool);
    function getDIDString(address _user) external view returns (string memory);
    function setAttribute(bytes32 _name, bytes calldata _value, uint256 _validity) external;
    function revokeAttribute(bytes32 _name, bytes calldata _value) external;
    function verifySignature(address _identity, bytes32 _hash, bytes calldata _signature)
        external
        view
        returns (bool, address);
    function getTotalDIDs() external view returns (uint256);
    function getAttribute(address _identity, bytes32 _name) external view returns (bytes memory, uint256);
    function changed(address _identity) external view returns (uint256);

    // ============ AxiomPrivacyFacet Functions ============
    function privateRegister(
        bytes32 _contentHash,
        bytes32 _commitment,
        bytes32 _nullifierHash,
        bytes calldata _zkProof,
        string calldata _metadataURI
    ) external payable returns (bytes32);
    function verifyOwnership(bytes32 _recordId, bytes32 _commitment, bytes calldata _zkProof)
        external
        view
        returns (bool);
    function requestErasure(bytes32 _recordId, bytes calldata _ownershipProof) external returns (bytes32);
    function confirmErasure(bytes32 _requestId, bytes32 _proofOfCompliance) external;
    function getPrivateRecord(bytes32 _recordId) external view returns (AxiomTypesV2.PrivateRecord memory);
    function contentExists(bytes32 _contentHash) external view returns (bool);
    function nullifierUsed(bytes32 _nullifierHash) external view returns (bool);
    function isMetadataDeleted(bytes32 _recordId) external view returns (bool);
    function getGDPRRequest(bytes32 _requestId) external view returns (AxiomTypesV2.GDPRRequest memory);
    function getRecordsByCommitment(bytes32 _commitment) external view returns (bytes32[] memory);

    // ZK Verifier Management
    function setZKVerifier(address _verifier) external;
    function getZKVerifier() external view returns (address);
    function approveZKVerifierForProduction() external;
    function isZKVerifierProductionApproved() external view returns (bool);
}
