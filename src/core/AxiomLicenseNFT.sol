// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {ERC721EnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC2981} from "@openzeppelin/contracts/interfaces/IERC2981.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IAxiomLicense} from "../interfaces/IAxiomLicense.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";

/**
 * @title AxiomLicenseNFT
 * @author Axiom Protocol Team
 * @notice ERC-721 License NFT with ERC-2981 royalty support for Programmable IP
 * @dev This contract manages:
 *      - License template creation by content owners
 *      - License purchase (mints NFT to buyer)
 *      - Sublicensing with revenue sharing
 *      - Royalty distribution following ERC-2981
 *
 *      Payment Methods:
 *      - Native ETH (paymentToken = address(0))
 *      - Any ERC-20 token
 */
contract AxiomLicenseNFT is 
    Initializable,
    ERC721Upgradeable,
    ERC721EnumerableUpgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    IERC2981,
    IAxiomLicense
{
    using SafeERC20 for IERC20;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Role for license managers
    bytes32 public constant LICENSE_MANAGER_ROLE = keccak256("LICENSE_MANAGER_ROLE");
    
    /// @notice Role for upgraders
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    
    /// @notice Basis points denominator (100%)
    uint16 public constant BPS_DENOMINATOR = 10000;
    
    /// @notice Protocol fee in basis points (5%)
    uint16 public constant PROTOCOL_FEE_BPS = 500;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              STORAGE
    // ═══════════════════════════════════════════════════════════════════════════

    bytes32 private constant LICENSE_STORAGE_SLOT = keccak256("axiom.license.nft.storage.v1");

    /// @dev Reentrancy lock status
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private _reentrancyStatus;

    /// @dev Custom reentrancy guard modifier
    modifier nonReentrant() {
        require(_reentrancyStatus != ENTERED, "ReentrancyGuard: reentrant call");
        _reentrancyStatus = ENTERED;
        _;
        _reentrancyStatus = NOT_ENTERED;
    }

    struct LicenseStorage {
        /// @notice Counter for license template IDs
        uint256 nextLicenseId;
        
        /// @notice Counter for NFT token IDs
        uint256 nextTokenId;
        
        /// @notice Maps license template ID to License struct
        mapping(uint256 => AxiomTypesV2.License) licenses;
        
        /// @notice Maps record ID to array of license IDs
        mapping(bytes32 => uint256[]) recordLicenses;
        
        /// @notice Maps token ID to license template ID
        mapping(uint256 => uint256) tokenToLicense;
        
        /// @notice Maps token ID to purchase details
        mapping(uint256 => AxiomTypesV2.LicensePurchase) purchases;
        
        /// @notice Maps record ID to royalty split configuration
        mapping(bytes32 => AxiomTypesV2.RoyaltySplit) royaltySplits;
        
        /// @notice Maps (token => recipient => amount) for pending royalties
        mapping(address => mapping(address => uint256)) pendingRoyalties;
        
        /// @notice Maps record ID to token to pending amounts
        mapping(bytes32 => mapping(address => uint256)) recordRoyalties;
        
        /// @notice Protocol treasury address
        address treasury;
        
        /// @notice Registry contract address (for content verification)
        address registry;
        
        /// @notice Sublicense counter
        uint256 nextSublicenseId;
        
        /// @notice Maps sublicense ID to parent token ID
        mapping(uint256 => uint256) sublicenseParent;
    }

    function _getLicenseStorage() internal pure returns (LicenseStorage storage s) {
        bytes32 slot = LICENSE_STORAGE_SLOT;
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
     * @notice Initialize the License NFT contract
     * @param _admin Admin address
     * @param _treasury Protocol treasury for fees
     * @param _registry Axiom Registry address
     */
    function initialize(
        address _admin,
        address _treasury,
        address _registry
    ) external initializer {
        __ERC721_init("Axiom License", "AXLICENSE");
        __ERC721Enumerable_init();
        __AccessControl_init();
        
        // Initialize reentrancy guard
        _reentrancyStatus = NOT_ENTERED;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(LICENSE_MANAGER_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        LicenseStorage storage s = _getLicenseStorage();
        s.treasury = _treasury;
        s.registry = _registry;
        s.nextLicenseId = 1;
        s.nextTokenId = 1;
        s.nextSublicenseId = 1;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          LICENSE CREATION
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomLicense
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
    ) external override returns (uint256 licenseId) {
        LicenseStorage storage s = _getLicenseStorage();
        
        // Validate royalty
        if (_royaltyBps > BPS_DENOMINATOR) {
            revert AxiomTypesV2.InvalidRoyaltySplit(_royaltyBps);
        }
        
        // Custom type requires terms URI
        if (_licenseType == AxiomTypesV2.LicenseType.CUSTOM && bytes(_customTermsURI).length == 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        licenseId = s.nextLicenseId++;

        s.licenses[licenseId] = AxiomTypesV2.License({
            recordId: _recordId,
            licensor: msg.sender,
            licensee: address(0), // Available for purchase
            paymentToken: _paymentToken,
            licenseType: _licenseType,
            royaltyBps: _royaltyBps,
            exclusive: _exclusive,
            sublicensable: _sublicensable,
            transferable: true,
            active: true,
            validFrom: uint40(block.timestamp),
            validUntil: _validUntil,
            price: _price,
            customTermsURI: _customTermsURI,
            territoryRestrictions: ""
        });

        s.recordLicenses[_recordId].push(licenseId);

        emit LicenseCreated(licenseId, _recordId, msg.sender, _licenseType, _price);
    }

    /// @inheritdoc IAxiomLicense
    function updateLicense(
        uint256 _licenseId,
        uint256 _price,
        uint40 _validUntil,
        bool _exclusive
    ) external override {
        LicenseStorage storage s = _getLicenseStorage();
        
        AxiomTypesV2.License storage license = s.licenses[_licenseId];
        
        if (license.licensor != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, license.licensor);
        }
        
        // Can only update if no purchases yet (check by looking at licensee for exclusive)
        if (license.exclusive && license.licensee != address(0)) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        license.price = _price;
        license.validUntil = _validUntil;
        license.exclusive = _exclusive;
    }

    /// @inheritdoc IAxiomLicense
    function deactivateLicense(uint256 _licenseId) external override {
        LicenseStorage storage s = _getLicenseStorage();
        
        AxiomTypesV2.License storage license = s.licenses[_licenseId];
        
        if (license.licensor != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, license.licensor);
        }

        license.active = false;

        emit LicenseDeactivated(_licenseId, msg.sender);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          LICENSE PURCHASE
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomLicense
    function purchaseLicense(
        uint256 _licenseId,
        uint40 _duration
    ) external payable override nonReentrant returns (uint256 tokenId) {
        return _purchaseLicense(_licenseId, msg.sender, _duration);
    }

    /// @inheritdoc IAxiomLicense
    function purchaseLicenseFor(
        uint256 _licenseId,
        address _recipient,
        uint40 _duration
    ) external payable override nonReentrant returns (uint256 tokenId) {
        if (_recipient == address(0)) {
            revert AxiomTypesV2.ZeroAddress();
        }
        return _purchaseLicense(_licenseId, _recipient, _duration);
    }

    function _purchaseLicense(
        uint256 _licenseId,
        address _recipient,
        uint40 _duration
    ) internal returns (uint256 tokenId) {
        LicenseStorage storage s = _getLicenseStorage();
        
        AxiomTypesV2.License storage license = s.licenses[_licenseId];
        
        // Validations
        if (!license.active) {
            revert AxiomTypesV2.LicenseNotFound(_licenseId);
        }
        
        if (license.exclusive && license.licensee != address(0)) {
            revert AxiomTypesV2.LicenseAlreadyPurchased(_licenseId);
        }
        
        // Check expiry
        if (license.validUntil > 0 && license.validUntil < block.timestamp) {
            revert AxiomTypesV2.LicenseExpired(_licenseId, license.validUntil);
        }

        // Process payment
        uint256 price = license.price;
        _processPayment(license.paymentToken, price, license.licensor, license.recordId);

        // Mint NFT
        tokenId = s.nextTokenId++;
        _safeMint(_recipient, tokenId);

        // Record purchase
        uint40 expiresAt = _duration > 0 ? uint40(block.timestamp) + _duration : license.validUntil;
        
        s.tokenToLicense[tokenId] = _licenseId;
        s.purchases[tokenId] = AxiomTypesV2.LicensePurchase({
            licenseId: _licenseId,
            tokenId: tokenId,
            buyer: _recipient,
            pricePaid: price,
            purchasedAt: uint40(block.timestamp),
            expiresAt: expiresAt
        });

        // Mark exclusive license
        if (license.exclusive) {
            license.licensee = _recipient;
        }

        emit LicensePurchased(_licenseId, tokenId, _recipient, price);
    }

    function _processPayment(
        address _token,
        uint256 _amount,
        address _licensor,
        bytes32 _recordId
    ) internal {
        LicenseStorage storage s = _getLicenseStorage();
        
        if (_amount == 0) return;

        // Calculate splits
        uint256 protocolFee = (_amount * PROTOCOL_FEE_BPS) / BPS_DENOMINATOR;
        uint256 licensorAmount = _amount - protocolFee;

        if (_token == address(0)) {
            // ETH payment
            if (msg.value < _amount) {
                revert AxiomTypesV2.InsufficientFee(msg.value, _amount);
            }

            // Send to treasury
            (bool success1,) = payable(s.treasury).call{value: protocolFee}("");
            require(success1, "Treasury transfer failed");

            // Check if there's a royalty split
            AxiomTypesV2.RoyaltySplit storage split = s.royaltySplits[_recordId];
            if (split.recipients.length > 0) {
                _distributeRoyaltiesETH(licensorAmount, split);
            } else {
                // Send all to licensor
                (bool success2,) = payable(_licensor).call{value: licensorAmount}("");
                require(success2, "Licensor transfer failed");
            }

            // Refund excess
            if (msg.value > _amount) {
                (bool success3,) = payable(msg.sender).call{value: msg.value - _amount}("");
                require(success3, "Refund failed");
            }
        } else {
            // ERC-20 payment
            IERC20 token = IERC20(_token);
            
            // Transfer to contract first
            token.safeTransferFrom(msg.sender, address(this), _amount);
            
            // Send protocol fee
            token.safeTransfer(s.treasury, protocolFee);

            // Check royalty split
            AxiomTypesV2.RoyaltySplit storage split = s.royaltySplits[_recordId];
            if (split.recipients.length > 0) {
                _distributeRoyaltiesERC20(token, licensorAmount, split);
            } else {
                token.safeTransfer(_licensor, licensorAmount);
            }
        }
    }

    function _distributeRoyaltiesETH(
        uint256 _amount,
        AxiomTypesV2.RoyaltySplit storage _split
    ) internal {
        for (uint256 i = 0; i < _split.recipients.length; i++) {
            uint256 share = (_amount * _split.shares[i]) / BPS_DENOMINATOR;
            if (share > 0) {
                (bool success,) = payable(_split.recipients[i]).call{value: share}("");
                require(success, "Royalty transfer failed");
            }
        }
    }

    function _distributeRoyaltiesERC20(
        IERC20 _token,
        uint256 _amount,
        AxiomTypesV2.RoyaltySplit storage _split
    ) internal {
        for (uint256 i = 0; i < _split.recipients.length; i++) {
            uint256 share = (_amount * _split.shares[i]) / BPS_DENOMINATOR;
            if (share > 0) {
                _token.safeTransfer(_split.recipients[i], share);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          SUBLICENSING
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomLicense
    function createSublicense(
        uint256 _parentTokenId,
        uint256 _price,
        uint40 _validUntil
    ) external override returns (uint256 sublicenseId) {
        LicenseStorage storage s = _getLicenseStorage();
        
        // Verify ownership
        if (ownerOf(_parentTokenId) != msg.sender) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        // Get parent license
        uint256 parentLicenseId = s.tokenToLicense[_parentTokenId];
        AxiomTypesV2.License storage parentLicense = s.licenses[parentLicenseId];
        
        // Check sublicensable
        if (!parentLicense.sublicensable) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        // Validate expiry
        AxiomTypesV2.LicensePurchase storage parentPurchase = s.purchases[_parentTokenId];
        if (parentPurchase.expiresAt > 0 && _validUntil > parentPurchase.expiresAt) {
            _validUntil = parentPurchase.expiresAt;
        }

        sublicenseId = s.nextSublicenseId++;

        // Create sublicense as new license template
        s.licenses[sublicenseId] = AxiomTypesV2.License({
            recordId: parentLicense.recordId,
            licensor: msg.sender, // Sublicensor
            licensee: address(0),
            paymentToken: parentLicense.paymentToken,
            licenseType: parentLicense.licenseType,
            royaltyBps: parentLicense.royaltyBps,
            exclusive: false, // Sublicenses are never exclusive
            sublicensable: false, // Cannot sub-sublicense
            transferable: true,
            active: true,
            validFrom: uint40(block.timestamp),
            validUntil: _validUntil,
            price: _price,
            customTermsURI: parentLicense.customTermsURI,
            territoryRestrictions: parentLicense.territoryRestrictions
        });

        s.sublicenseParent[sublicenseId] = _parentTokenId;

        emit SublicenseCreated(sublicenseId, _parentTokenId, msg.sender);
    }

    /// @inheritdoc IAxiomLicense
    function purchaseSublicense(uint256 _sublicenseId) 
        external payable override nonReentrant 
        returns (uint256 tokenId) 
    {
        // Purchase follows same flow as regular license
        return _purchaseLicense(_sublicenseId, msg.sender, 0);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ROYALTY MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomLicense
    function setRoyaltySplit(
        bytes32 _recordId,
        address[] calldata _recipients,
        uint16[] calldata _shares
    ) external override {
        if (_recipients.length != _shares.length) {
            revert AxiomTypesV2.ArrayLengthMismatch();
        }

        // Verify total shares = 100%
        uint256 totalShares = 0;
        for (uint256 i = 0; i < _shares.length; i++) {
            if (_recipients[i] == address(0)) {
                revert AxiomTypesV2.ZeroAddress();
            }
            totalShares += _shares[i];
        }
        
        if (totalShares != BPS_DENOMINATOR) {
            revert AxiomTypesV2.InvalidRoyaltySplit(totalShares);
        }

        LicenseStorage storage s = _getLicenseStorage();
        
        s.royaltySplits[_recordId] = AxiomTypesV2.RoyaltySplit({
            recipients: _recipients,
            shares: _shares,
            autoDistribute: true
        });

        emit RoyaltySplitUpdated(_recordId, _recipients, _shares);
    }

    /// @inheritdoc IAxiomLicense
    function claimRoyalties(bytes32 _recordId) external override returns (uint256 amount) {
        return _claimRoyalties(_recordId, address(0));
    }

    /// @inheritdoc IAxiomLicense
    function claimRoyaltiesToken(bytes32 _recordId, address _token) 
        external override 
        returns (uint256 amount) 
    {
        return _claimRoyalties(_recordId, _token);
    }

    function _claimRoyalties(bytes32 _recordId, address _token) internal returns (uint256 amount) {
        LicenseStorage storage s = _getLicenseStorage();
        
        amount = s.pendingRoyalties[_token][msg.sender];
        
        if (amount == 0) return 0;

        s.pendingRoyalties[_token][msg.sender] = 0;

        if (_token == address(0)) {
            (bool success,) = payable(msg.sender).call{value: amount}("");
            require(success, "Transfer failed");
        } else {
            IERC20(_token).safeTransfer(msg.sender, amount);
        }

        emit RoyaltyDistributed(_recordId, msg.sender, amount, _token);
    }

    /// @inheritdoc IAxiomLicense
    function pendingRoyalties(address _recipient, bytes32) 
        external view override 
        returns (uint256 pending) 
    {
        LicenseStorage storage s = _getLicenseStorage();
        return s.pendingRoyalties[address(0)][_recipient];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ERC-2981 ROYALTY INFO
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IERC2981
    function royaltyInfo(uint256 _tokenId, uint256 _salePrice)
        external view override(IERC2981, IAxiomLicense)
        returns (address receiver, uint256 royaltyAmount)
    {
        LicenseStorage storage s = _getLicenseStorage();
        
        uint256 licenseId = s.tokenToLicense[_tokenId];
        AxiomTypesV2.License storage license = s.licenses[licenseId];
        
        // Return primary royalty recipient (licensor)
        receiver = license.licensor;
        royaltyAmount = (_salePrice * license.royaltyBps) / BPS_DENOMINATOR;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          LICENSE QUERIES
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomLicense
    function getLicense(uint256 _licenseId) 
        external view override 
        returns (AxiomTypesV2.License memory license) 
    {
        LicenseStorage storage s = _getLicenseStorage();
        return s.licenses[_licenseId];
    }

    /// @inheritdoc IAxiomLicense
    function getLicensesByRecord(bytes32 _recordId) 
        external view override 
        returns (uint256[] memory licenseIds) 
    {
        LicenseStorage storage s = _getLicenseStorage();
        return s.recordLicenses[_recordId];
    }

    /// @inheritdoc IAxiomLicense
    function getLicensesByOwner(address _owner) 
        external view override 
        returns (uint256[] memory tokenIds) 
    {
        uint256 balance = balanceOf(_owner);
        tokenIds = new uint256[](balance);
        
        for (uint256 i = 0; i < balance; i++) {
            tokenIds[i] = tokenOfOwnerByIndex(_owner, i);
        }
    }

    /// @inheritdoc IAxiomLicense
    function hasValidLicense(address _licensee, bytes32 _recordId) 
        external view override 
        returns (bool isValid, AxiomTypesV2.LicenseType licenseType) 
    {
        LicenseStorage storage s = _getLicenseStorage();
        
        uint256[] memory licenseIds = s.recordLicenses[_recordId];
        
        for (uint256 i = 0; i < licenseIds.length; i++) {
            AxiomTypesV2.License storage license = s.licenses[licenseIds[i]];
            
            // Check if licensee owns any token for this license
            if (license.licensee == _licensee) {
                // Check expiry
                if (license.validUntil == 0 || license.validUntil > block.timestamp) {
                    return (true, license.licenseType);
                }
            }
        }
        
        // Check all owned tokens
        uint256 balance = balanceOf(_licensee);
        for (uint256 i = 0; i < balance; i++) {
            uint256 tokenId = tokenOfOwnerByIndex(_licensee, i);
            AxiomTypesV2.LicensePurchase storage purchase = s.purchases[tokenId];
            uint256 licenseId = s.tokenToLicense[tokenId];
            AxiomTypesV2.License storage license = s.licenses[licenseId];
            
            if (license.recordId == _recordId) {
                if (purchase.expiresAt == 0 || purchase.expiresAt > block.timestamp) {
                    return (true, license.licenseType);
                }
            }
        }
        
        return (false, AxiomTypesV2.LicenseType.NONE);
    }

    /// @inheritdoc IAxiomLicense
    function isLicenseValid(uint256 _tokenId) external view override returns (bool isValid) {
        LicenseStorage storage s = _getLicenseStorage();
        
        AxiomTypesV2.LicensePurchase storage purchase = s.purchases[_tokenId];
        
        if (purchase.purchasedAt == 0) {
            return false;
        }
        
        if (purchase.expiresAt > 0 && purchase.expiresAt < block.timestamp) {
            return false;
        }
        
        uint256 licenseId = s.tokenToLicense[_tokenId];
        return s.licenses[licenseId].active;
    }

    /// @inheritdoc IAxiomLicense
    function getRoyaltySplit(bytes32 _recordId) 
        external view override 
        returns (AxiomTypesV2.RoyaltySplit memory split) 
    {
        LicenseStorage storage s = _getLicenseStorage();
        return s.royaltySplits[_recordId];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          TERRITORY MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomLicense
    function setTerritoryRestrictions(
        uint256 _licenseId,
        string calldata _restrictionsURI
    ) external override {
        LicenseStorage storage s = _getLicenseStorage();
        
        AxiomTypesV2.License storage license = s.licenses[_licenseId];
        
        if (license.licensor != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, license.licensor);
        }

        license.territoryRestrictions = _restrictionsURI;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ADMIN FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Update treasury address
     * @param _newTreasury New treasury address
     */
    function setTreasury(address _newTreasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_newTreasury == address(0)) {
            revert AxiomTypesV2.ZeroAddress();
        }
        LicenseStorage storage s = _getLicenseStorage();
        s.treasury = _newTreasury;
    }

    /**
     * @notice Get treasury address
     */
    function getTreasury() external view returns (address) {
        LicenseStorage storage s = _getLicenseStorage();
        return s.treasury;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          REQUIRED OVERRIDES
    // ═══════════════════════════════════════════════════════════════════════════

    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
        returns (address)
    {
        return super._update(to, tokenId, auth);
    }

    function _increaseBalance(address account, uint128 value)
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
    {
        super._increaseBalance(account, value);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable, AccessControlUpgradeable, IERC165)
        returns (bool)
    {
        return 
            interfaceId == type(IERC2981).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyRole(UPGRADER_ROLE) 
    {}

    // Required for receiving ETH
    receive() external payable {}
}
