// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {IAxiomDID} from "../interfaces/IAxiomDID.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";
import {AxiomStorage} from "../storage/AxiomStorage.sol";

/**
 * @title AxiomDIDRegistry
 * @author Axiom Protocol Team
 * @notice Diamond Facet for Decentralized Identifier (DID) management
 * @dev V3: Converted to stateless facet. Executes via delegatecall from AxiomRouter.
 *
 *      W3C DID Core and ERC-1056 standards compliance:
 *      - DID registration and resolution
 *      - Delegate authorization for signing
 *      - Verification levels (NONE → GOVERNMENT)
 *      - Attribute management (ERC-1056 compatible)
 *
 *      Storage Pattern: Uses Diamond Storage with separate DID_STORAGE_SLOT
 *      (does not collide with AXIOM_STORAGE_POSITION)
 *
 *      Access Control: Checks Router's AccessControl via delegatecall context
 *      (VERIFIER_ROLE is stored in Router's AccessControlUpgradeable storage)
 */
contract AxiomDIDRegistry is IAxiomDID {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Role for identity verifiers (KYC/KYB providers)
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /// @notice Role for contract upgraders (defined in Router)
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

        /// @notice Whether an address has ever been added to an identity's delegate list
        mapping(address => mapping(address => bool)) delegateListed;
    }

    function _getDIDStorage() internal pure returns (DIDStorage storage s) {
        bytes32 slot = DID_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ACCESS CONTROL HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Check if caller has a specific role
     * @notice Reads from Router's AccessControlUpgradeable storage via delegatecall
     *         The Router inherits AccessControlUpgradeable, and under delegatecall,
     *         we execute in Router's storage context, so we can access its roles.
     */
    function _hasRole(bytes32 role, address account) internal view returns (bool) {
        // When called via delegatecall, 'this' is the Router proxy address
        // We can directly call hasRole on the Router's AccessControl
        return IAccessControl(address(this)).hasRole(role, account);
    }

    /**
     * @dev Require caller has a specific role
     */
    modifier onlyRole(bytes32 role) {
        require(_hasRole(role, msg.sender), "DIDRegistry: Missing required role");
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
    //                          DID REGISTRATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Registers a new DID linked to the caller's wallet address.
     * @dev The DID string should follow did:ethr format. Requires non-empty DID and valid document hash.
     * @param _did The full DID string (e.g., "did:ethr:1:0x123...").
     * @param _didDocumentHash IPFS hash (CID) of the DID Document.
     * @param _publicKeyJwk Public key in JWK format for signature verification.
     */
    function registerDID(string calldata _did, bytes32 _didDocumentHash, string calldata _publicKeyJwk)
        external
        override
        whenNotPaused
        notBanned
    {
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
        if (bytes(_publicKeyJwk).length == 0) {
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

    /**
     * @notice Updates an existing DID Document.
     * @dev Only the identity owner can update their DID Document. DID must be active.
     * @param _newDocumentHash The new IPFS hash of the updated DID Document.
     */
    function updateDIDDocument(bytes32 _newDocumentHash) external override whenNotPaused {
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

    /**
     * @notice Sets the service endpoint for the DID.
     * @dev Stores the endpoint URL in the registry. Emits DIDAttributeChanged.
     * @param _serviceEndpoint The URL of the service endpoint.
     */
    function setServiceEndpoint(string calldata _serviceEndpoint) external override whenNotPaused {
        DIDStorage storage s = _getDIDStorage();

        _requireActiveDID(msg.sender);

        s.identities[msg.sender].serviceEndpoint = _serviceEndpoint;
        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDAttributeChanged(
            msg.sender, keccak256("did/svc/endpoint"), bytes(_serviceEndpoint), type(uint256).max, previousChange
        );
    }

    /**
     * @notice Revokes (deactivates) the caller's DID permanently.
     * @dev This action is irreversible. The DID cannot be re-activated.
     */
    function revokeDID() external override whenNotPaused {
        DIDStorage storage s = _getDIDStorage();

        _requireActiveDID(msg.sender);

        s.identities[msg.sender].isActive = false;
        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDAttributeChanged(
            msg.sender, keccak256("did/revoked"), abi.encode(true), block.timestamp, previousChange
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          DELEGATE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Adds a delegate authorized to act on behalf of the identity.
     * @dev Delegates can sign content registrations and other actions.
     * @param _delegate The address of the delegate.
     * @param _delegateType The type of delegation (keccak256 hash of type string).
     * @param _validity The duration in seconds for which the delegation is valid.
     */
    function addDelegate(address _delegate, bytes32 _delegateType, uint256 _validity) external override whenNotPaused {
        DIDStorage storage s = _getDIDStorage();

        _requireActiveDID(msg.sender);

        if (_delegate == address(0)) {
            revert AxiomTypesV2.ZeroAddress();
        }
        if (_validity == 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        if (
            _delegateType != DELEGATE_TYPE_SIG_AUTH && _delegateType != DELEGATE_TYPE_VERI_KEY
                && _delegateType != DELEGATE_TYPE_AXIOM_REG
        ) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        uint256 validTo = block.timestamp + _validity;
        if (validTo > type(uint40).max) revert AxiomTypesV2.OperationNotPermitted();

        // Add to delegate list if new
        if (!s.delegateListed[msg.sender][_delegate]) {
            s.delegateList[msg.sender].push(_delegate);
            s.delegateListed[msg.sender][_delegate] = true;
        }

        s.delegates[msg.sender][_delegateType][_delegate] = validTo;
        s.delegateActive[msg.sender][_delegateType][_delegate] = true;

        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDDelegateChanged(msg.sender, _delegateType, _delegate, validTo, previousChange);
    }

    /**
     * @notice Revokes a delegate's authorization.
     * @dev Immediately invalidates the delegate regardless of original validity period.
     * @param _delegate The address of the delegate to revoke.
     * @param _delegateType The type of delegation being revoked.
     */
    function revokeDelegate(address _delegate, bytes32 _delegateType) external override whenNotPaused {
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

    /**
     * @notice Checks if a delegate is currently valid for an identity.
     * @param _identity The identity (DID owner) address.
     * @param _delegateType The type of delegation to check.
     * @param _delegate The address of the potential delegate.
     * @return isValid True if the delegate is active and the validity period has not expired.
     */
    function validDelegate(address _identity, bytes32 _delegateType, address _delegate)
        external
        view
        override
        returns (bool isValid)
    {
        DIDStorage storage s = _getDIDStorage();

        if (!s.identities[_identity].isActive) {
            return false;
        }

        // Keep this public query identical to the predicate used by
        // signature authorization: a delegate is invalid after the DID
        // itself expires or is revoked, even if the delegate's own timestamp
        // has not elapsed yet.
        return _isDelegateActive(s, _identity, _delegateType, _delegate);
    }

    /**
     * @notice Retrieves all active delegates for an identity.
     * @param _identity The identity address.
     * @return delegates An array of DIDDelegate structs representing active delegates.
     */
    function getDelegates(address _identity)
        external
        view
        override
        returns (AxiomTypesV2.DIDDelegate[] memory delegates)
    {
        DIDStorage storage s = _getDIDStorage();

        address[] memory delegateAddrs = s.delegateList[_identity];
        uint256 count = 0;

        bytes32[3] memory types = [DELEGATE_TYPE_SIG_AUTH, DELEGATE_TYPE_VERI_KEY, DELEGATE_TYPE_AXIOM_REG];

        // Count every active (address, delegateType) authorization.
        for (uint256 i = 0; i < delegateAddrs.length; i++) {
            for (uint256 t = 0; t < types.length; t++) {
                if (_isDelegateActive(s, _identity, types[t], delegateAddrs[i])) count++;
            }
        }

        delegates = new AxiomTypesV2.DIDDelegate[](count);
        uint256 idx = 0;

        for (uint256 i = 0; i < delegateAddrs.length && idx < count; i++) {
            address del = delegateAddrs[i];

            for (uint256 t = 0; t < types.length; t++) {
                if (_isDelegateActive(s, _identity, types[t], del)) {
                    delegates[idx] = AxiomTypesV2.DIDDelegate({
                        delegate: del,
                        delegateType: types[t],
                        validUntil: uint40(s.delegates[_identity][types[t]][del]),
                        isActive: true
                    });
                    idx++;
                }
            }
        }
    }

    function _isDelegateActive(DIDStorage storage s, address _identity, bytes32 _delegateType, address _delegate)
        internal
        view
        returns (bool)
    {
        AxiomTypesV2.DIDIdentity storage identity = s.identities[_identity];
        return identity.isActive && (identity.validUntil == 0 || identity.validUntil > block.timestamp)
            && s.delegateActive[_identity][_delegateType][_delegate]
            && s.delegates[_identity][_delegateType][_delegate] > block.timestamp;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                     VERIFICATION LEVEL MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Sets the verification level for an identity.
     * @dev Requires VERIFIER_ROLE. Verification is performed off-chain.
     * @param _user The address of the identity to verify.
     * @param _level The new verification level to assign.
     */
    function setVerificationLevel(address _user, AxiomTypesV2.VerificationLevel _level)
        external
        override
        onlyRole(VERIFIER_ROLE)
        whenNotPaused
    {
        DIDStorage storage s = _getDIDStorage();

        _requireActiveDID(_user);

        AxiomTypesV2.VerificationLevel oldLevel = s.identities[_user].level;
        s.identities[_user].level = _level;

        emit VerificationLevelChanged(_user, oldLevel, _level, msg.sender);
    }

    /**
     * @notice Retrieves the current verification level for an identity.
     * @param _user The address to check.
     * @return level The current verification level.
     */
    function getVerificationLevel(address _user) external view override returns (AxiomTypesV2.VerificationLevel level) {
        DIDStorage storage s = _getDIDStorage();
        return s.identities[_user].level;
    }

    /**
     * @notice Checks if an identity meets a minimum verification requirement.
     * @param _user The address to check.
     * @param _minLevel The minimum required verification level.
     * @return meetsRequirement True if the identity's level is greater than or equal to _minLevel.
     */
    function meetsVerificationLevel(address _user, AxiomTypesV2.VerificationLevel _minLevel)
        external
        view
        override
        returns (bool meetsRequirement)
    {
        DIDStorage storage s = _getDIDStorage();

        if (!s.identities[_user].isActive) {
            return false;
        }

        return uint8(s.identities[_user].level) >= uint8(_minLevel);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                            DID RESOLUTION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Resolves a DID string to its full identity information.
     * @param _did The DID string to resolve.
     * @return identity The full DIDIdentity struct.
     */
    function resolveDID(string calldata _did)
        external
        view
        override
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

    /**
     * @notice Retrieves the identity information for a wallet address.
     * @param _user The wallet address to look up.
     * @return identity The full DIDIdentity struct.
     */
    function getIdentity(address _user) external view override returns (AxiomTypesV2.DIDIdentity memory identity) {
        DIDStorage storage s = _getDIDStorage();
        return s.identities[_user];
    }

    /**
     * @notice Checks if an address has a registered DID.
     * @param _user The address to check.
     * @return exists True if a DID exists for this address.
     */
    function hasDID(address _user) external view override returns (bool exists) {
        DIDStorage storage s = _getDIDStorage();
        return bytes(s.identities[_user].did).length > 0;
    }

    /**
     * @notice Checks if a DID is currently active.
     * @param _user The address of the DID owner.
     * @return active True if the DID is registered, active, and not expired.
     */
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
        if (identity.validUntil > 0 && identity.validUntil <= block.timestamp) {
            return false;
        }

        return true;
    }

    /**
     * @notice Retrieves the DID string for an address.
     * @param _user The address to look up.
     * @return did The DID string.
     */
    function getDIDString(address _user) external view override returns (string memory did) {
        DIDStorage storage s = _getDIDStorage();
        return s.identities[_user].did;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                      ERC-1056 ATTRIBUTE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Sets an attribute for a DID (ERC-1056 compatible).
     * @dev Attributes are stored with a validity period.
     * @param _name The attribute name (hashed).
     * @param _value The attribute value.
     * @param _validity The duration in seconds for which the attribute is valid.
     */
    function setAttribute(bytes32 _name, bytes calldata _value, uint256 _validity) external override whenNotPaused {
        DIDStorage storage s = _getDIDStorage();

        _requireActiveDID(msg.sender);

        uint256 validTo = block.timestamp + _validity;

        s.attributes[msg.sender][_name] = _value;
        s.attributeValidity[msg.sender][_name] = validTo;

        uint256 previousChange = s.changed[msg.sender];
        s.changed[msg.sender] = block.number;

        emit DIDAttributeChanged(msg.sender, _name, _value, validTo, previousChange);
    }

    /**
     * @notice Revokes an attribute.
     * @dev Sets the attribute validity to 0.
     * @param _name The attribute name to revoke.
     * @param _value The attribute value to match for revocation.
     */
    function revokeAttribute(bytes32 _name, bytes calldata _value) external override whenNotPaused {
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

    /**
     * @notice Verifies if a signature was made by a valid identity or delegate.
     * @param _identity The claimed identity (DID owner).
     * @param _hash The message hash that was signed.
     * @param _signature The signature to verify.
     * @return isValid True if the signature is valid.
     * @return signer The address that signed the message.
     */
    function verifySignature(address _identity, bytes32 _hash, bytes calldata _signature)
        external
        view
        override
        returns (bool isValid, address signer)
    {
        DIDStorage storage s = _getDIDStorage();

        // Recover signer from signature
        bytes32 ethSignedHash = _hash.toEthSignedMessageHash();
        ECDSA.RecoverError error;
        (signer, error,) = ECDSA.tryRecoverCalldata(ethSignedHash, _signature);
        if (error != ECDSA.RecoverError.NoError) return (false, address(0));

        // Check if signer is the identity itself
        AxiomTypesV2.DIDIdentity storage identity = s.identities[_identity];
        if (
            signer == _identity && identity.isActive
                && (identity.validUntil == 0 || identity.validUntil > block.timestamp)
        ) {
            return (true, signer);
        }

        // Check if signer is a valid delegate
        if (
            _isDelegateActive(s, _identity, DELEGATE_TYPE_SIG_AUTH, signer)
                || _isDelegateActive(s, _identity, DELEGATE_TYPE_AXIOM_REG, signer)
        ) {
            return (true, signer);
        }

        return (false, signer);
    }

    /**
     * @notice Retrieves the current nonce for an identity (for replay protection).
     * @param _identity The identity address.
     * @return The current nonce value.
     */
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

        if (identity.validUntil > 0 && identity.validUntil <= block.timestamp) {
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
        external
        view
        returns (bytes memory value, uint256 validTo)
    {
        DIDStorage storage s = _getDIDStorage();
        return (s.attributes[_identity][_name], s.attributeValidity[_identity][_name]);
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
}
