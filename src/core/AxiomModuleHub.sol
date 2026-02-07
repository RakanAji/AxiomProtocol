// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title AxiomModuleHub
 * @author Axiom Protocol Team
 * @notice Central registry for all Axiom Protocol modules
 * @dev Enables modular architecture where Router orchestrates calls to updated modules
 */
contract AxiomModuleHub is 
    Initializable, 
    AccessControlUpgradeable, 
    UUPSUpgradeable 
{
    // ═══════════════════════════════════════════════════════════════════════════
    //                              CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════════

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant CONFIG_MANAGER_ROLE = keccak256("CONFIG_MANAGER_ROLE");

    // Module Keys
    bytes32 public constant KEY_DID_REGISTRY = keccak256("DID_REGISTRY");
    bytes32 public constant KEY_LICENSE_NFT = keccak256("LICENSE_NFT");
    bytes32 public constant KEY_DISPUTE_RESOLVER = keccak256("DISPUTE_RESOLVER");
    bytes32 public constant KEY_PRIVACY_MODULE = keccak256("PRIVACY_MODULE");
    bytes32 public constant KEY_PAYMASTER = keccak256("PAYMASTER");

    // ═══════════════════════════════════════════════════════════════════════════
    //                              STORAGE
    // ═══════════════════════════════════════════════════════════════════════════

    bytes32 private constant HUB_STORAGE_SLOT = keccak256("axiom.module.hub.storage.v1");

    struct HubStorage {
        /// @notice Maps module key -> Contract address
        mapping(bytes32 => address) modules;
        
        /// @notice Array of all registered keys for iteration
        bytes32[] moduleKeys;
    }

    function _getHubStorage() internal pure returns (HubStorage storage s) {
        bytes32 slot = HUB_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                              EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    event ModuleUpdated(bytes32 indexed key, address indexed newAddress, address indexed oldAddress);

    // ═══════════════════════════════════════════════════════════════════════════
    //                            INITIALIZER
    // ═══════════════════════════════════════════════════════════════════════════

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin) external initializer {
        __AccessControl_init();
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);
        _grantRole(CONFIG_MANAGER_ROLE, _admin);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          MODULE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Set or update a module address
     * @param _key Module identifier key
     * @param _moduleAddress New address of the module
     */
    function setModule(bytes32 _key, address _moduleAddress) external onlyRole(CONFIG_MANAGER_ROLE) {
        require(_moduleAddress != address(0), "Invalid module address");
        HubStorage storage s = _getHubStorage();
        
        address oldAddress = s.modules[_key];
        s.modules[_key] = _moduleAddress;
        
        // Track key if new
        if (oldAddress == address(0)) {
            s.moduleKeys.push(_key);
        }
        
        emit ModuleUpdated(_key, _moduleAddress, oldAddress);
    }

    /**
     * @notice Get module address by key
     * @param _key Module identifier key
     */
    function getModule(bytes32 _key) external view returns (address) {
        HubStorage storage s = _getHubStorage();
        return s.modules[_key];
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
