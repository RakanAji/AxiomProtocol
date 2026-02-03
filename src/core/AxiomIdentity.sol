// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {AxiomTypes} from "../libraries/AxiomTypes.sol";
import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {IAxiomIdentity} from "../interfaces/IAxiomIdentity.sol";

/**
 * @title AxiomIdentity
 * @author Axiom Protocol Team
 * @notice Identity management contract for DID resolution
 * @dev Maps wallet addresses to human-readable identities
 */
contract AxiomIdentity is Initializable, IAxiomIdentity {
    // ============ Modifiers ============

    /**
     * @dev Ensures caller has operator role (checked via router)
     */
    modifier onlyOperator() {
        // This will be enforced by AxiomRouter via access control
        _;
    }

    // ============ External Functions ============

    /**
     * @inheritdoc IAxiomIdentity
     */
    function registerIdentity(
        string calldata _name,
        string calldata _proofURI
    ) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Check if identity already exists
        if (bytes(s.identities[msg.sender].name).length > 0) {
            revert AxiomTypes.IdentityAlreadyExists(msg.sender);
        }
        
        // Check if name is already taken
        bytes32 nameHash = keccak256(abi.encodePacked(_name));
        require(s.nameToAddress[nameHash] == address(0), "Name already taken");
        
        // Store identity
        s.identities[msg.sender] = AxiomTypes.IdentityInfo({
            name: _name,
            proofURI: _proofURI,
            isVerified: false,
            registeredAt: uint40(block.timestamp)
        });
        
        // Store reverse lookup
        s.nameToAddress[nameHash] = msg.sender;
        
        emit AxiomTypes.IdentityRegistered(msg.sender, _name, _proofURI);
    }

    /**
     * @inheritdoc IAxiomIdentity
     */
    function updateIdentity(
        string calldata _name,
        string calldata _proofURI
    ) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Check identity exists
        if (bytes(s.identities[msg.sender].name).length == 0) {
            revert AxiomTypes.IdentityNotFound(msg.sender);
        }
        
        // Clear old name mapping
        bytes32 oldNameHash = keccak256(abi.encodePacked(s.identities[msg.sender].name));
        delete s.nameToAddress[oldNameHash];
        
        // Check if new name is available
        bytes32 newNameHash = keccak256(abi.encodePacked(_name));
        require(s.nameToAddress[newNameHash] == address(0), "Name already taken");
        
        // Update identity
        s.identities[msg.sender].name = _name;
        s.identities[msg.sender].proofURI = _proofURI;
        // Keep verification status - admin must re-verify if needed
        
        // Update reverse lookup
        s.nameToAddress[newNameHash] = msg.sender;
        
        emit AxiomTypes.IdentityRegistered(msg.sender, _name, _proofURI);
    }

    /**
     * @inheritdoc IAxiomIdentity
     */
    function verifyIdentity(address _user) external override onlyOperator {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Check identity exists
        if (bytes(s.identities[_user].name).length == 0) {
            revert AxiomTypes.IdentityNotFound(_user);
        }
        
        s.identities[_user].isVerified = true;
        
        emit AxiomTypes.IdentityVerified(_user, msg.sender);
    }

    /**
     * @inheritdoc IAxiomIdentity
     */
    function revokeVerification(address _user) external override onlyOperator {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Check identity exists
        if (bytes(s.identities[_user].name).length == 0) {
            revert AxiomTypes.IdentityNotFound(_user);
        }
        
        s.identities[_user].isVerified = false;
    }

    // ============ View Functions ============

    /**
     * @inheritdoc IAxiomIdentity
     */
    function resolveIdentity(address _user) 
        external view override returns (AxiomTypes.IdentityInfo memory info) 
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.identities[_user];
    }

    /**
     * @inheritdoc IAxiomIdentity
     */
    function isIdentityVerified(address _user) external view override returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.identities[_user].isVerified;
    }

    /**
     * @inheritdoc IAxiomIdentity
     */
    function resolveByName(string calldata _name) external view override returns (address) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        bytes32 nameHash = keccak256(abi.encodePacked(_name));
        return s.nameToAddress[nameHash];
    }
}
