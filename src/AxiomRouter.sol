// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {AxiomStorage} from "./storage/AxiomStorage.sol";
import {AxiomTypes} from "./libraries/AxiomTypes.sol";
import {IAxiomRegistry} from "./interfaces/IAxiomRegistry.sol";
import {IAxiomIdentity} from "./interfaces/IAxiomIdentity.sol";
import {IAxiomTreasury} from "./interfaces/IAxiomTreasury.sol";

/**
 * @title AxiomRouter
 * @author Axiom Protocol Team
 * @notice Main entry point for Axiom Protocol - UUPS Upgradeable proxy
 * @dev Consolidates all protocol functionality in a single upgradeable contract
 */
contract AxiomRouter is 
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuard,
    PausableUpgradeable,
    IAxiomRegistry,
    IAxiomIdentity,
    IAxiomTreasury
{
    // ============ Role Definitions ============

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant ENTERPRISE_ROLE = keccak256("ENTERPRISE_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // ============ Protocol Version ============
    
    string public constant VERSION = "1.0.0";

    // ============ Initializer ============

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the protocol
     * @param _admin Admin address
     * @param _treasuryWallet Treasury wallet for fee collection
     */
    function initialize(
        address _admin,
        address _treasuryWallet
    ) external initializer {
        __AccessControl_init();
        __Pausable_init();

        // Setup roles
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        // Initialize storage
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.baseFee = 0.0001 ether; // ~$0.25 at $2500/ETH
        s.treasuryWallet = _treasuryWallet;
        s.rateLimitWindow = 60; // 1 minute
        s.maxActionsPerWindow = 10;
        s.maxBatchSize = 100;
        s.protocolVersion = 1;
    }

    // ============ Modifiers ============

    modifier notBanned() {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        if (s.bannedAddresses[msg.sender]) {
            revert AxiomTypes.AddressBanned(msg.sender);
        }
        _;
    }

    modifier rateLimit() {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (!hasRole(ENTERPRISE_ROLE, msg.sender)) {
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

    // ============ Registry Functions ============

    /// @inheritdoc IAxiomRegistry
    function register(
        bytes32 _contentHash,
        string calldata _metadataURI
    ) external payable override nonReentrant notBanned whenNotPaused rateLimit returns (bytes32 recordId) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        recordId = AxiomStorage.generateRecordId(_contentHash, msg.sender);
        
        if (AxiomStorage.recordExists(recordId)) {
            revert AxiomTypes.ContentAlreadyExists(recordId);
        }
        
        uint256 requiredFee = _calculateFee(msg.sender);
        if (msg.value < requiredFee) {
            revert AxiomTypes.InsufficientFee(msg.value, requiredFee);
        }
        
        s.records[recordId] = AxiomTypes.AxiomRecord({
            issuer: msg.sender,
            timestamp: uint40(block.timestamp),
            status: AxiomTypes.ContentStatus.ACTIVE,
            algorithm: AxiomTypes.HashAlgorithm.SHA256,
            contentHash: _contentHash,
            metadataURI: _metadataURI
        });
        
        s.userRecords[msg.sender].push(recordId);
        s.hashExists[recordId] = true;
        s.totalRecords++;
        s.totalFeesCollected += requiredFee;
        
        emit AxiomTypes.ContentRegistered(recordId, msg.sender, _contentHash, uint40(block.timestamp), _metadataURI);
        emit AxiomTypes.FeeCollected(msg.sender, requiredFee, recordId);
        
        // Refund excess
        if (msg.value > requiredFee) {
            (bool success,) = payable(msg.sender).call{value: msg.value - requiredFee}("");
            require(success, "Refund failed");
        }
        
        return recordId;
    }

    /// @inheritdoc IAxiomRegistry
    function batchRegister(
        bytes32[] calldata _contentHashes,
        string[] calldata _metadataURIs
    ) external payable override nonReentrant notBanned whenNotPaused returns (bytes32[] memory recordIds) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (_contentHashes.length != _metadataURIs.length) {
            revert AxiomTypes.ArrayLengthMismatch();
        }
        
        if (_contentHashes.length > s.maxBatchSize) {
            revert AxiomTypes.BatchSizeExceeded(_contentHashes.length, s.maxBatchSize);
        }
        
        uint256 feePerItem = _calculateFee(msg.sender);
        uint256 totalFee = feePerItem * _contentHashes.length;
        
        if (msg.value < totalFee) {
            revert AxiomTypes.InsufficientFee(msg.value, totalFee);
        }
        
        recordIds = new bytes32[](_contentHashes.length);
        uint256 successCount = 0;
        
        for (uint256 i = 0; i < _contentHashes.length; i++) {
            bytes32 recordId = AxiomStorage.generateRecordId(_contentHashes[i], msg.sender);
            
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
            successCount++;
            
            emit AxiomTypes.ContentRegistered(recordId, msg.sender, _contentHashes[i], uint40(block.timestamp), _metadataURIs[i]);
        }
        
        uint256 actualFee = feePerItem * successCount;
        s.totalFeesCollected += actualFee;
        
        // Refund for failed registrations
        if (msg.value > actualFee) {
            (bool success,) = payable(msg.sender).call{value: msg.value - actualFee}("");
            require(success, "Refund failed");
        }
        
        return recordIds;
    }

    /// @inheritdoc IAxiomRegistry
    function revoke(bytes32 _recordId, string calldata _reason) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (!AxiomStorage.recordExists(_recordId)) {
            revert AxiomTypes.ContentNotFound(_recordId);
        }
        
        AxiomTypes.AxiomRecord storage record = s.records[_recordId];
        
        if (record.issuer != msg.sender) {
            revert AxiomTypes.NotIssuer(msg.sender, record.issuer);
        }
        
        if (record.status == AxiomTypes.ContentStatus.REVOKED) {
            revert AxiomTypes.ContentAlreadyRevoked(_recordId);
        }
        
        record.status = AxiomTypes.ContentStatus.REVOKED;
        
        emit AxiomTypes.ContentRevoked(_recordId, msg.sender, _reason);
    }

    /// @inheritdoc IAxiomRegistry
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
        isValid = (record.status == AxiomTypes.ContentStatus.ACTIVE);
        
        return (isValid, record);
    }

    /// @inheritdoc IAxiomRegistry
    function getRecord(bytes32 _recordId) external view override returns (AxiomTypes.AxiomRecord memory) {
        if (!AxiomStorage.recordExists(_recordId)) {
            revert AxiomTypes.ContentNotFound(_recordId);
        }
        
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.records[_recordId];
    }

    /// @inheritdoc IAxiomRegistry
    function getRecordsByIssuer(address _issuer) external view override returns (bytes32[] memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.userRecords[_issuer];
    }

    /// @inheritdoc IAxiomRegistry
    function getTotalRecords() external view override returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.totalRecords;
    }

    // ============ Identity Functions ============

    /// @inheritdoc IAxiomIdentity
    function registerIdentity(string calldata _name, string calldata _proofURI) external override notBanned {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (bytes(s.identities[msg.sender].name).length > 0) {
            revert AxiomTypes.IdentityAlreadyExists(msg.sender);
        }
        
        bytes32 nameHash = keccak256(abi.encodePacked(_name));
        require(s.nameToAddress[nameHash] == address(0), "Name already taken");
        
        s.identities[msg.sender] = AxiomTypes.IdentityInfo({
            name: _name,
            proofURI: _proofURI,
            isVerified: false,
            registeredAt: uint40(block.timestamp)
        });
        
        s.nameToAddress[nameHash] = msg.sender;
        
        emit AxiomTypes.IdentityRegistered(msg.sender, _name, _proofURI);
    }

    /// @inheritdoc IAxiomIdentity
    function updateIdentity(string calldata _name, string calldata _proofURI) external override notBanned {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (bytes(s.identities[msg.sender].name).length == 0) {
            revert AxiomTypes.IdentityNotFound(msg.sender);
        }
        
        bytes32 oldNameHash = keccak256(abi.encodePacked(s.identities[msg.sender].name));
        delete s.nameToAddress[oldNameHash];
        
        bytes32 newNameHash = keccak256(abi.encodePacked(_name));
        require(s.nameToAddress[newNameHash] == address(0), "Name already taken");
        
        s.identities[msg.sender].name = _name;
        s.identities[msg.sender].proofURI = _proofURI;
        s.nameToAddress[newNameHash] = msg.sender;
        
        emit AxiomTypes.IdentityRegistered(msg.sender, _name, _proofURI);
    }

    /// @inheritdoc IAxiomIdentity
    function verifyIdentity(address _user) external override onlyRole(OPERATOR_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (bytes(s.identities[_user].name).length == 0) {
            revert AxiomTypes.IdentityNotFound(_user);
        }
        
        s.identities[_user].isVerified = true;
        
        emit AxiomTypes.IdentityVerified(_user, msg.sender);
    }

    /// @inheritdoc IAxiomIdentity
    function revokeVerification(address _user) external override onlyRole(OPERATOR_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (bytes(s.identities[_user].name).length == 0) {
            revert AxiomTypes.IdentityNotFound(_user);
        }
        
        s.identities[_user].isVerified = false;
    }

    /// @inheritdoc IAxiomIdentity
    function resolveIdentity(address _user) external view override returns (AxiomTypes.IdentityInfo memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.identities[_user];
    }

    /// @inheritdoc IAxiomIdentity
    function isIdentityVerified(address _user) external view override returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.identities[_user].isVerified;
    }

    /// @inheritdoc IAxiomIdentity
    function resolveByName(string calldata _name) external view override returns (address) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.nameToAddress[keccak256(abi.encodePacked(_name))];
    }

    // ============ Treasury Functions ============

    /// @inheritdoc IAxiomTreasury
    function getFee(address _user) external view override returns (uint256) {
        return _calculateFee(_user);
    }

    /// @inheritdoc IAxiomTreasury
    function setBaseFee(uint256 _fee) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.baseFee = _fee;
    }

    /// @inheritdoc IAxiomTreasury
    function setEnterpriseRate(address _user, uint256 _rate) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.enterpriseRates[_user] = _rate;
    }

    /// @inheritdoc IAxiomTreasury
    function grantEnterpriseStatus(address _user) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(ENTERPRISE_ROLE, _user);
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.isEnterprise[_user] = true;
    }

    /// @inheritdoc IAxiomTreasury
    function revokeEnterpriseStatus(address _user) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(ENTERPRISE_ROLE, _user);
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.isEnterprise[_user] = false;
    }

    /// @inheritdoc IAxiomTreasury
    function withdraw(address _to, uint256 _amount) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_to != address(0), "Invalid recipient");
        require(address(this).balance >= _amount, "Insufficient balance");
        
        (bool success,) = payable(_to).call{value: _amount}("");
        require(success, "Transfer failed");
    }

    /// @inheritdoc IAxiomTreasury
    function setTreasuryWallet(address _wallet) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_wallet != address(0), "Invalid address");
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.treasuryWallet = _wallet;
    }

    /// @inheritdoc IAxiomTreasury
    function getBaseFee() external view override returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.baseFee;
    }

    /// @inheritdoc IAxiomTreasury
    function getTotalFeesCollected() external view override returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.totalFeesCollected;
    }

    /// @inheritdoc IAxiomTreasury
    function isEnterpriseUser(address _user) external view override returns (bool) {
        return hasRole(ENTERPRISE_ROLE, _user);
    }

    // ============ Admin Functions ============

    /**
     * @notice Ban an address
     */
    function banAddress(address _user, string calldata _reason) external onlyRole(OPERATOR_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.bannedAddresses[_user] = true;
    }

    /**
     * @notice Unban an address
     */
    function unbanAddress(address _user) external onlyRole(OPERATOR_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.bannedAddresses[_user] = false;
    }

    /**
     * @notice Dispute content
     */
    function disputeContent(bytes32 _recordId, string calldata _reason) external onlyRole(OPERATOR_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (!AxiomStorage.recordExists(_recordId)) {
            revert AxiomTypes.ContentNotFound(_recordId);
        }
        
        s.records[_recordId].status = AxiomTypes.ContentStatus.DISPUTED;
        
        emit AxiomTypes.ContentDisputed(_recordId, msg.sender, _reason);
    }

    /**
     * @notice Pause the protocol
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the protocol
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @notice Set rate limit
     */
    function setRateLimit(uint256 _window, uint256 _maxActions) external onlyRole(DEFAULT_ADMIN_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.rateLimitWindow = _window;
        s.maxActionsPerWindow = _maxActions;
    }

    /**
     * @notice Set max batch size
     */
    function setMaxBatchSize(uint256 _size) external onlyRole(DEFAULT_ADMIN_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.maxBatchSize = _size;
    }

    /**
     * @notice Check if address is banned
     */
    function isBanned(address _user) external view returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.bannedAddresses[_user];
    }

    // ============ Internal Functions ============

    function _calculateFee(address _user) internal view returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (hasRole(ENTERPRISE_ROLE, _user) && s.enterpriseRates[_user] > 0) {
            return s.enterpriseRates[_user];
        }
        
        return s.baseFee;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    // ============ Receive ETH ============

    receive() external payable {}
}
