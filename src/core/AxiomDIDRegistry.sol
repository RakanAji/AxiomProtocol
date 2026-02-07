// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IAxiomDID} from "../interfaces/IAxiomDID.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";

/**
 * @title AxiomDIDRegistry
 * @author Axiom Protocol Team
 * @notice Decentralized Identifier (DID) Registry following W3C DID Core and ERC-1056 standards
 * @dev This contract manages:
 *      - DID registration and resolution
 *      - Delegate authorization for signing
 *      - Verification levels (NONE → GOVERNMENT)
 *      - Attribute management (ERC-1056 compatible)
 *
 *      Storage Pattern: Uses Diamond Storage for upgradeability
 *      Access Control: VERIFIER_ROLE for setting verification levels
 */
contract AxiomDIDRegistry is 
    Initializable, 
    AccessControlUpgradeable, 
    UUPSUpgradeable,
    IAxiomDID 
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Role for identity verifiers (KYC/KYB providers)
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    
    /// @notice Role for contract upgraders
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Standard delegate type for signature authorization
    bytes32 public constant DELEGATE_TYPE_SIG_AUTH = keccak256("sigAuth");
    
    /// @notice Standard delegate type for verification keys
    bytes32 public constant DELEGATE_TYPE_VERI_KEY = keccak256("veriKey");
    
    /// @notice Delegate type for Axiom content registration
    bytes32 public constant DELEGATE_TYPE_AXIOM_REG = keccak256("axiomReg");

    // ═══════════════════════════════════════════════════════════════════════════
    //                              STORAGE
    // ═══════════════════════════════════════════════════════════════════════════

    /// @dev Storage slot for DID registry (Diamond pattern)
    bytes32 private constant DID_STORAGE_SLOT = keccak256("axiom.did.registry.storage.v1");

    struct DIDStorage {
        /// @notice Maps address to DID identity
        mapping(address => AxiomTypesV2.DIDIdentity) identities;
        
        /// @notice Maps DID string hash to owner address (reverse lookup)
        mapping(bytes32 => address) didToOwner;
        
        /// @notice Maps identity => delegateType => delegate => validity timestamp
        mapping(address => mapping(bytes32 => mapping(address => uint256))) delegates;
        
        /// @notice Maps identity => delegate list for enumeration
        mapping(address => address[]) delegateList;
        
        /// @notice Maps identity => delegateType => delegate => active status
        mapping(address => mapping(bytes32 => mapping(address => bool))) delegateActive;
        
        /// @notice Maps identity => attribute name => value (ERC-1056)
        mapping(address => mapping(bytes32 => bytes)) attributes;
        
        /// @notice Maps identity => attribute name => validity timestamp
        mapping(address => mapping(bytes32 => uint256)) attributeValidity;
        
        /// @notice Block of last change per identity (ERC-1056 compat)
        mapping(address => uint256) changed;
        
        /// @notice Nonce per identity for replay protection
        mapping(address => uint256) nonces;
        
        /// @notice Total registered DIDs
        uint256 totalDIDs;
    }

    function _getDIDStorage() internal pure returns (DIDStorage storage s) {
        bytes32 slot = DID_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                            INITIALIZER
    // ═══════════════════════════════════════════════════════════════════════════

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the DID Registry
     * @param _admin Admin address with DEFAULT_ADMIN_ROLE
     */
    function initialize(address _admin) external initializer {
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(VERIFIER_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          DID REGISTRATION
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomDID
    function registerDID(
        string calldata _did,
        bytes32 _didDocumentHash,
        string calldata _publicKeyJwk
    ) external override {
        DIDStorage storage s = _getDIDStorage();
        
        // Validation
        if (bytes(s.identities[msg.sender].did).length > 0) {
            revert AxiomTypesV2.DIDAlreadyExists(msg.sender);
        }
        if (bytes(_did).length == 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        if (_didDocumentHash == bytes32(0)) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        bytes32 didHash = keccak256(bytes(_did));
        if (s.didToOwner[didHash] != address(0)) {
            revert AxiomTypesV2.DIDAlreadyExists(s.didToOwner[didHash]);
        }

        // Create identity
        s.identities[msg.sender] = AxiomTypesV2.DIDIdentity({
            level: AxiomTypesV2.VerificationLevel.NONE,
            isActive: true,
            validUntil: 0, // No expiry by default
            registeredAt: uint40(block.timestamp),
            didDocumentHash: _didDocumentHash,
            did: _did,
            publicKeyJwk: _publicKeyJwk,
            serviceEndpoint: ""
        });

        s.didToOwner[didHash] = msg.sender;
        s.changed[msg.sender] = block.number;
        s.totalDIDs++;

        emit DIDRegistered(msg.sender, _did, _didDocumentHash);
    }

    /// @inheritdoc IAxiomDID
    function updateDIDDocument(bytes32 _newDocumentHash) external override {
        DIDStorage storage s = _getDIDStorage();
        
        _requireActiveDID(msg.sender);
        
        if (_newDocumentHash == bytes32(0)) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        s.identities[msg.sender].didDocumentHash = _newDocumentHash;
        s.changed[msg.sender] = block.number;

        emit DIDAttributeChanged(
            msg.sender,
            keccak256("did/document"),
            abi.encode(_newDocumentHash),
            type(uint256).max,
            s.changed[msg.sender]
        );
    }

    /// @inheritdoc IAxiomDID
    function setServiceEndpoint(string calldata _serviceEndpoint) external override {
        DIDStorage storage s = _getDIDStorage();
        
        _requireActiveDID(msg.sender);

        s.identities[msg.sender].serviceEndpoint = _serviceEndpoint;
        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDAttributeChanged(
            msg.sender,
            keccak256("did/svc/endpoint"),
            bytes(_serviceEndpoint),
            type(uint256).max,
            previousChange
        );
    }

    /// @inheritdoc IAxiomDID
    function revokeDID() external override {
        DIDStorage storage s = _getDIDStorage();
        
        _requireActiveDID(msg.sender);

        s.identities[msg.sender].isActive = false;
        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDAttributeChanged(
            msg.sender,
            keccak256("did/revoked"),
            abi.encode(true),
            block.timestamp,
            previousChange
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          DELEGATE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomDID
    function addDelegate(
        address _delegate,
        bytes32 _delegateType,
        uint256 _validity
    ) external override {
        DIDStorage storage s = _getDIDStorage();
        
        _requireActiveDID(msg.sender);
        
        if (_delegate == address(0)) {
            revert AxiomTypesV2.ZeroAddress();
        }
        if (_validity == 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        uint256 validTo = block.timestamp + _validity;
        
        // Add to delegate list if new
        if (!s.delegateActive[msg.sender][_delegateType][_delegate]) {
            s.delegateList[msg.sender].push(_delegate);
        }
        
        s.delegates[msg.sender][_delegateType][_delegate] = validTo;
        s.delegateActive[msg.sender][_delegateType][_delegate] = true;
        
        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDDelegateChanged(
            msg.sender,
            _delegateType,
            _delegate,
            validTo,
            previousChange
        );
    }

    /// @inheritdoc IAxiomDID
    function revokeDelegate(address _delegate, bytes32 _delegateType) external override {
        DIDStorage storage s = _getDIDStorage();
        
        _requireActiveDID(msg.sender);
        
        if (!s.delegateActive[msg.sender][_delegateType][_delegate]) {
            revert AxiomTypesV2.UnauthorizedDelegate(msg.sender, _delegate);
        }

        s.delegates[msg.sender][_delegateType][_delegate] = 0;
        s.delegateActive[msg.sender][_delegateType][_delegate] = false;
        
        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDDelegateChanged(
            msg.sender,
            _delegateType,
            _delegate,
            0, // validity = 0 means revoked
            previousChange
        );
    }

    /// @inheritdoc IAxiomDID
    function validDelegate(
        address _identity,
        bytes32 _delegateType,
        address _delegate
    ) external view override returns (bool isValid) {
        DIDStorage storage s = _getDIDStorage();
        
        if (!s.identities[_identity].isActive) {
            return false;
        }
        
        uint256 validTo = s.delegates[_identity][_delegateType][_delegate];
        return validTo > block.timestamp;
    }

    /// @inheritdoc IAxiomDID
    function getDelegates(address _identity) 
        external view override 
        returns (AxiomTypesV2.DIDDelegate[] memory delegates) 
    {
        DIDStorage storage s = _getDIDStorage();
        
        address[] memory delegateAddrs = s.delegateList[_identity];
        uint256 count = 0;
        
        // Count active delegates
        for (uint256 i = 0; i < delegateAddrs.length; i++) {
            // Check common delegate types
            if (_isDelegateActive(s, _identity, DELEGATE_TYPE_SIG_AUTH, delegateAddrs[i]) ||
                _isDelegateActive(s, _identity, DELEGATE_TYPE_VERI_KEY, delegateAddrs[i]) ||
                _isDelegateActive(s, _identity, DELEGATE_TYPE_AXIOM_REG, delegateAddrs[i])) {
                count++;
            }
        }
        
        delegates = new AxiomTypesV2.DIDDelegate[](count);
        uint256 idx = 0;
        
        for (uint256 i = 0; i < delegateAddrs.length && idx < count; i++) {
            address del = delegateAddrs[i];
            
            // Check each delegate type
            bytes32[3] memory types = [DELEGATE_TYPE_SIG_AUTH, DELEGATE_TYPE_VERI_KEY, DELEGATE_TYPE_AXIOM_REG];
            
            for (uint256 t = 0; t < types.length; t++) {
                if (_isDelegateActive(s, _identity, types[t], del)) {
                    delegates[idx] = AxiomTypesV2.DIDDelegate({
                        delegate: del,
                        delegateType: types[t],
                        validUntil: uint40(s.delegates[_identity][types[t]][del]),
                        isActive: true
                    });
                    idx++;
                    break; // Only add once per delegate
                }
            }
        }
    }

    function _isDelegateActive(
        DIDStorage storage s,
        address _identity,
        bytes32 _delegateType,
        address _delegate
    ) internal view returns (bool) {
        return s.delegateActive[_identity][_delegateType][_delegate] &&
               s.delegates[_identity][_delegateType][_delegate] > block.timestamp;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                     VERIFICATION LEVEL MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomDID
    function setVerificationLevel(
        address _user,
        AxiomTypesV2.VerificationLevel _level
    ) external override onlyRole(VERIFIER_ROLE) {
        DIDStorage storage s = _getDIDStorage();
        
        _requireActiveDID(_user);

        AxiomTypesV2.VerificationLevel oldLevel = s.identities[_user].level;
        s.identities[_user].level = _level;

        emit VerificationLevelChanged(_user, oldLevel, _level, msg.sender);
    }

    /// @inheritdoc IAxiomDID
    function getVerificationLevel(address _user) 
        external view override 
        returns (AxiomTypesV2.VerificationLevel level) 
    {
        DIDStorage storage s = _getDIDStorage();
        return s.identities[_user].level;
    }

    /// @inheritdoc IAxiomDID
    function meetsVerificationLevel(
        address _user,
        AxiomTypesV2.VerificationLevel _minLevel
    ) external view override returns (bool meetsRequirement) {
        DIDStorage storage s = _getDIDStorage();
        
        if (!s.identities[_user].isActive) {
            return false;
        }
        
        return uint8(s.identities[_user].level) >= uint8(_minLevel);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                            DID RESOLUTION
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomDID
    function resolveDID(string calldata _did) 
        external view override 
        returns (AxiomTypesV2.DIDIdentity memory identity) 
    {
        DIDStorage storage s = _getDIDStorage();
        
        bytes32 didHash = keccak256(bytes(_did));
        address owner = s.didToOwner[didHash];
        
        if (owner == address(0)) {
            return identity; // Empty struct
        }
        
        return s.identities[owner];
    }

    /// @inheritdoc IAxiomDID
    function getIdentity(address _user) 
        external view override 
        returns (AxiomTypesV2.DIDIdentity memory identity) 
    {
        DIDStorage storage s = _getDIDStorage();
        return s.identities[_user];
    }

    /// @inheritdoc IAxiomDID
    function hasDID(address _user) external view override returns (bool exists) {
        DIDStorage storage s = _getDIDStorage();
        return bytes(s.identities[_user].did).length > 0;
    }

    /// @inheritdoc IAxiomDID
    function isDIDActive(address _user) external view override returns (bool active) {
        DIDStorage storage s = _getDIDStorage();
        
        AxiomTypesV2.DIDIdentity storage identity = s.identities[_user];
        
        if (bytes(identity.did).length == 0) {
            return false;
        }
        
        if (!identity.isActive) {
            return false;
        }
        
        // Check expiry if set
        if (identity.validUntil > 0 && identity.validUntil < block.timestamp) {
            return false;
        }
        
        return true;
    }

    /// @inheritdoc IAxiomDID
    function getDIDString(address _user) 
        external view override 
        returns (string memory did) 
    {
        DIDStorage storage s = _getDIDStorage();
        return s.identities[_user].did;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                      ERC-1056 ATTRIBUTE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomDID
    function setAttribute(
        bytes32 _name,
        bytes calldata _value,
        uint256 _validity
    ) external override {
        DIDStorage storage s = _getDIDStorage();
        
        _requireActiveDID(msg.sender);

        uint256 validTo = block.timestamp + _validity;
        
        s.attributes[msg.sender][_name] = _value;
        s.attributeValidity[msg.sender][_name] = validTo;
        
        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDAttributeChanged(
            msg.sender,
            _name,
            _value,
            validTo,
            previousChange
        );
    }

    /// @inheritdoc IAxiomDID
    function revokeAttribute(bytes32 _name, bytes calldata _value) external override {
        DIDStorage storage s = _getDIDStorage();
        
        _requireActiveDID(msg.sender);

        // Verify attribute matches
        bytes32 storedHash = keccak256(s.attributes[msg.sender][_name]);
        bytes32 providedHash = keccak256(_value);
        
        if (storedHash != providedHash) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        s.attributeValidity[msg.sender][_name] = 0;
        
        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDAttributeChanged(
            msg.sender,
            _name,
            _value,
            0, // validity = 0 means revoked
            previousChange
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          SIGNATURE VALIDATION
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomDID
    function verifySignature(
        address _identity,
        bytes32 _hash,
        bytes calldata _signature
    ) external view override returns (bool isValid, address signer) {
        DIDStorage storage s = _getDIDStorage();
        
        // Recover signer from signature
        bytes32 ethSignedHash = _hash.toEthSignedMessageHash();
        signer = ethSignedHash.recover(_signature);
        
        // Check if signer is the identity itself
        if (signer == _identity && s.identities[_identity].isActive) {
            return (true, signer);
        }
        
        // Check if signer is a valid delegate
        if (_isDelegateActive(s, _identity, DELEGATE_TYPE_SIG_AUTH, signer) ||
            _isDelegateActive(s, _identity, DELEGATE_TYPE_AXIOM_REG, signer)) {
            return (true, signer);
        }
        
        return (false, signer);
    }

    /// @inheritdoc IAxiomDID
    function nonce(address _identity) external view override returns (uint256) {
        DIDStorage storage s = _getDIDStorage();
        return s.nonces[_identity];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          INTERNAL FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Require that the user has an active DID
     */
    function _requireActiveDID(address _user) internal view {
        DIDStorage storage s = _getDIDStorage();
        
        AxiomTypesV2.DIDIdentity storage identity = s.identities[_user];
        
        if (bytes(identity.did).length == 0) {
            revert AxiomTypesV2.DIDNotFound(_user);
        }
        
        if (!identity.isActive) {
            revert AxiomTypesV2.DIDRevoked(_user);
        }
        
        if (identity.validUntil > 0 && identity.validUntil < block.timestamp) {
            revert AxiomTypesV2.DIDExpired(_user, identity.validUntil);
        }
    }

    /**
     * @dev Increment nonce for replay protection
     */
    function _useNonce(address _identity) internal returns (uint256) {
        DIDStorage storage s = _getDIDStorage();
        return s.nonces[_identity]++;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get total number of registered DIDs
     * @return Total DID count
     */
    function getTotalDIDs() external view returns (uint256) {
        DIDStorage storage s = _getDIDStorage();
        return s.totalDIDs;
    }

    /**
     * @notice Get attribute value for an identity
     * @param _identity Identity address
     * @param _name Attribute name
     * @return value Attribute value
     * @return validTo Validity timestamp
     */
    function getAttribute(address _identity, bytes32 _name) 
        external view 
        returns (bytes memory value, uint256 validTo) 
    {
        DIDStorage storage s = _getDIDStorage();
        return (
            s.attributes[_identity][_name],
            s.attributeValidity[_identity][_name]
        );
    }

    /**
     * @notice Get block number of last change for identity
     * @param _identity Identity address
     * @return Block number of last change
     */
    function changed(address _identity) external view returns (uint256) {
        DIDStorage storage s = _getDIDStorage();
        return s.changed[_identity];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                              UUPS
    // ═══════════════════════════════════════════════════════════════════════════

    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyRole(UPGRADER_ROLE) 
    {}
}
