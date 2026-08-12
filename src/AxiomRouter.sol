// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "./utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {AxiomStorage} from "./storage/AxiomStorage.sol";

/**
 * @title AxiomRouter
 * @author Axiom Protocol Team
 * @notice Diamond Proxy for Axiom Protocol - Routes calls to facets via delegatecall
 * @dev V3 Upgrade: Converted from monolithic contract to Diamond Pattern proxy.
 *      All business logic moved to facets (AxiomRegistry, AxiomDIDRegistry, etc.).
 *
 *      Architecture:
 *      - AxiomRouter = Diamond Proxy (this contract)
 *      - AxiomRegistry = Facet for content registration/verification
 *      - AxiomDIDRegistry = Facet for DID management
 *
 *      Storage: All facets share AxiomStorage via delegatecall, enabling
 *      unified state across the protocol.
 */
contract AxiomRouter is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    bytes4 private constant INTERFACE_ID_ERC721 = 0x80ac58cd;
    bytes4 private constant INTERFACE_ID_ERC721_METADATA = 0x5b5e139f;
    bytes4 private constant INTERFACE_ID_ERC2981 = 0x2a55205a;

    // ============ Role Definitions ============

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant ENTERPRISE_ROLE = keccak256("ENTERPRISE_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // ============ Protocol Version ============

    string public constant VERSION = "5.0.0";

    // ============ Events ============

    event FacetAdded(bytes4 indexed selector, address indexed facetAddress);
    event FacetRemoved(bytes4 indexed selector, address indexed facetAddress);
    event FacetReplaced(bytes4 indexed selector, address indexed oldFacet, address indexed newFacet);

    // ============ Errors ============

    error FacetNotFound(bytes4 selector);
    error FacetAlreadyExists(bytes4 selector);
    error InvalidFacetAddress();

    // ============ Initializer ============

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the Diamond proxy
     * @param _admin Admin address with all roles
     * @param _treasuryWallet Treasury wallet for fee collection
     */
    function initialize(address _admin, address _treasuryWallet) external initializer {
        if (_admin == address(0) || _treasuryWallet == address(0)) {
            revert InvalidFacetAddress();
        }
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

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
        s.protocolVersion = 5;
        s.reentrancyStatus = 1;
    }

    // ============ Diamond Facet Management ============

    /**
     * @notice Add function selectors to route to a facet
     * @dev Only callable by DEFAULT_ADMIN_ROLE
     * @param _facetAddress Address of the facet contract
     * @param _selectors Array of function selectors to route to this facet
     */
    function addFacetSelectors(address _facetAddress, bytes4[] calldata _selectors)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (_facetAddress == address(0) || _facetAddress.code.length == 0) {
            revert InvalidFacetAddress();
        }
        if (_selectors.length == 0) revert FacetNotFound(bytes4(0));

        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        // Track if this is a new facet address
        bool isNewFacet = true;
        for (uint256 i = 0; i < s.facetAddresses.length; i++) {
            if (s.facetAddresses[i] == _facetAddress) {
                isNewFacet = false;
                break;
            }
        }

        if (isNewFacet) {
            s.facetAddresses.push(_facetAddress);
        }

        // Register selectors
        for (uint256 i = 0; i < _selectors.length; i++) {
            bytes4 selector = _selectors[i];
            if (selector == bytes4(0)) revert FacetNotFound(selector);
            address existingFacet = s.selectorToFacet[selector];

            if (existingFacet == address(0)) {
                // New selector
                s.selectorToFacet[selector] = _facetAddress;
                emit FacetAdded(selector, _facetAddress);
            } else if (existingFacet != _facetAddress) {
                // Replace existing selector
                s.selectorToFacet[selector] = _facetAddress;
                emit FacetReplaced(selector, existingFacet, _facetAddress);
            }
            // If existingFacet == _facetAddress, no-op (already registered)
        }
    }

    /**
     * @notice Remove function selectors (unregister from routing)
     * @dev Only callable by DEFAULT_ADMIN_ROLE
     * @param _selectors Array of function selectors to remove
     */
    function removeFacetSelectors(bytes4[] calldata _selectors) external onlyRole(DEFAULT_ADMIN_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        for (uint256 i = 0; i < _selectors.length; i++) {
            bytes4 selector = _selectors[i];
            address facet = s.selectorToFacet[selector];

            if (facet == address(0)) revert FacetNotFound(selector);

            delete s.selectorToFacet[selector];
            emit FacetRemoved(selector, facet);
        }
    }

    /**
     * @notice Get the facet address for a function selector
     * @param _selector The function selector
     * @return facetAddr Address of the facet that handles this selector
     */
    function facetAddress(bytes4 _selector) external view returns (address facetAddr) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.selectorToFacet[_selector];
    }

    /**
     * @notice Get all registered facet addresses
     * @return facets Array of facet contract addresses
     */
    function facetAddresses() external view returns (address[] memory facets) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.facetAddresses;
    }

    /**
     * @notice Report interfaces implemented natively or by the installed license facet.
     * @dev This selector is intentionally native so it must not be routed to a facet.
     */
    function supportsInterface(bytes4 interfaceId) public view override(AccessControlUpgradeable) returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        bool erc721 = _hasSelectors(
            s,
            [
                bytes4(keccak256("balanceOf(address)")),
                bytes4(keccak256("ownerOf(uint256)")),
                bytes4(keccak256("safeTransferFrom(address,address,uint256)")),
                bytes4(keccak256("safeTransferFrom(address,address,uint256,bytes)")),
                bytes4(keccak256("transferFrom(address,address,uint256)")),
                bytes4(keccak256("approve(address,uint256)")),
                bytes4(keccak256("setApprovalForAll(address,bool)")),
                bytes4(keccak256("getApproved(uint256)")),
                bytes4(keccak256("isApprovedForAll(address,address)"))
            ]
        );
        bool metadata = erc721 && s.selectorToFacet[bytes4(keccak256("name()"))] != address(0)
            && s.selectorToFacet[bytes4(keccak256("symbol()"))] != address(0)
            && s.selectorToFacet[bytes4(keccak256("tokenURI(uint256)"))] != address(0);
        bool royalty = s.selectorToFacet[bytes4(keccak256("royaltyInfo(uint256,uint256)"))] != address(0);

        return (interfaceId == INTERFACE_ID_ERC721 && erc721)
            || (interfaceId == INTERFACE_ID_ERC721_METADATA && metadata)
            || (interfaceId == INTERFACE_ID_ERC2981 && royalty) || super.supportsInterface(interfaceId);
    }

    function _hasSelectors(AxiomStorage.Storage storage s, bytes4[9] memory selectors) internal view returns (bool) {
        for (uint256 i = 0; i < selectors.length; i++) {
            if (s.selectorToFacet[selectors[i]] == address(0)) return false;
        }
        return true;
    }

    // ============ Diamond Fallback (Delegatecall Routing) ============

    /**
     * @notice Fallback function routes calls to appropriate facets via delegatecall
     * @dev Looks up facet by msg.sig and delegates execution.
     *      Delegatecall preserves msg.sender and executes in Router's storage context.
     */
    fallback() external payable {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        address facet = s.selectorToFacet[msg.sig];

        if (facet == address(0)) {
            revert FacetNotFound(msg.sig);
        }

        // Delegatecall to facet
        assembly {
            // Copy calldata to memory
            calldatacopy(0, 0, calldatasize())

            // Delegatecall to facet
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)

            // Copy return data to memory
            returndatacopy(0, 0, returndatasize())

            // Return or revert based on result
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    /**
     * @notice Receive function for direct ETH transfers
     */
    receive() external payable {}

    // ============ Admin Functions ============

    /**
     * @notice Pause the protocol
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.paused = true;
    }

    /**
     * @notice Unpause the protocol
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.paused = false;
    }

    // ============ UUPS Upgrade Authorization ============

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}
}
