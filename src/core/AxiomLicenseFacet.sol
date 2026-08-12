// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC2981} from "@openzeppelin/contracts/interfaces/IERC2981.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {AxiomTypes} from "../libraries/AxiomTypes.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";
import {IAxiomLicense} from "../interfaces/IAxiomLicense.sol";

interface ILicenseRouterAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

/**
 * @title AxiomLicenseFacet
 * @author Axiom Protocol Team
 * @notice Diamond Facet for Programmable IP Licensing with ERC-721 NFT implementation
 * @dev Stateless facet executed via delegatecall from AxiomRouter.
 *      Implements ERC-721 and ERC-2981 manually without inheritance (Diamond Pattern requirement).
 *      The AxiomRouter (Diamond Proxy) address IS the NFT collection address.
 *
 *      Payment Methods:
 *      - Native ETH (paymentToken = address(0))
 *      - Any ERC-20 token
 *
 *      CRITICAL: All state stored in AxiomStorage. No state variables in this contract.
 */
contract AxiomLicenseFacet is IAxiomLicense, IERC165 {
    using SafeERC20 for IERC20;
    using Strings for uint256;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Basis points denominator (100%)
    uint16 public constant BPS_DENOMINATOR = 10000;

    /// @notice Protocol fee in basis points (5%)
    uint16 public constant PROTOCOL_FEE_BPS = 500;
    bytes32 private constant DEFAULT_ADMIN_ROLE = 0x00;

    // ERC-721 Interface ID
    bytes4 private constant INTERFACE_ID_ERC721 = 0x80ac58cd;

    // ERC-721 Metadata Interface ID
    bytes4 private constant INTERFACE_ID_ERC721_METADATA = 0x5b5e139f;

    // ERC-2981 Interface ID
    bytes4 private constant INTERFACE_ID_ERC2981 = 0x2a55205a;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              MODIFIERS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Reentrancy protection using shared storage
     */
    modifier nonReentrant() {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        require(s.reentrancyStatus != 2, "ReentrancyGuard: reentrant call");
        s.reentrancyStatus = 2;
        _;
        s.reentrancyStatus = 1;
    }

    /**
     * @dev Validates token exists
     */
    modifier tokenExists(uint256 _tokenId) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        require(s.tokenOwner[_tokenId] != address(0), "ERC721: token does not exist");
        _;
    }

    modifier whenNotPaused() {
        require(!AxiomStorage.getStorage().paused, "Protocol is paused");
        _;
    }

    modifier onlyAdmin() {
        require(
            ILicenseRouterAccessControl(address(this)).hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "LicenseFacet: missing admin role"
        );
        _;
    }

    modifier notBanned() {
        if (AxiomStorage.getStorage().bannedAddresses[msg.sender]) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        _;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          LICENSE TEMPLATE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    function setLicenseTreasury(address _treasury) external override onlyAdmin {
        if (_treasury == address(0)) {
            revert AxiomTypesV2.ZeroAddress();
        }
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        address oldTreasury = s.licenseTreasury;
        s.licenseTreasury = _treasury;
        emit LicenseTreasuryUpdated(oldTreasury, _treasury);
    }

    function getLicenseTreasury() external view override returns (address) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.licenseTreasury != address(0) ? s.licenseTreasury : s.treasuryWallet;
    }

    /**
     * @notice Creates a new license template for registered content.
     * @dev Only the content issuer can create licenses. Validates royalty and logical constraints.
     * @param _recordId The content record ID this license applies to.
     * @param _licenseType The type of license (CC-BY, Commercial, etc.).
     * @param _price The price in payment token (or ETH if paymentToken is 0x0).
     * @param _paymentToken The ERC-20 token for payment (0x0 for ETH).
     * @param _royaltyBps The royalty percentage in basis points (250 = 2.5%).
     * @param _validUntil The license expiration timestamp (0 for perpetual).
     * @param _exclusive If true, only one licensee allowed.
     * @param _sublicensable If true, licensee can create sublicenses.
     * @param _customTermsURI IPFS URI to full license terms (required for CUSTOM type).
     * @return licenseId The unique identifier for the created license.
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
    ) external override whenNotPaused notBanned returns (uint256 licenseId) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        address issuer = _getActiveRecordIssuer(s, _recordId);
        if (issuer != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, issuer);
        }

        if (_licenseType == AxiomTypesV2.LicenseType.NONE) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        // Validate royalty
        if (_royaltyBps > BPS_DENOMINATOR) {
            revert AxiomTypesV2.InvalidRoyaltySplit(_royaltyBps);
        }

        // Custom type requires terms URI
        if (_licenseType == AxiomTypesV2.LicenseType.CUSTOM && bytes(_customTermsURI).length == 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        if (_validUntil != 0 && _validUntil <= block.timestamp) {
            revert AxiomTypesV2.LicenseExpired(0, _validUntil);
        }

        if (_paymentToken != address(0) && _paymentToken.code.length == 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        // Initialize counters if needed
        if (s.nextLicenseId == 0) {
            s.nextLicenseId = 1;
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

    /**
     * @notice Updates license terms (before any purchases).
     * @dev Can only be updated if no licenses have been sold.
     * @param _licenseId The License ID to update.
     * @param _price The new price.
     * @param _validUntil The new expiration timestamp.
     * @param _exclusive The new exclusivity setting.
     */
    function updateLicense(uint256 _licenseId, uint256 _price, uint40 _validUntil, bool _exclusive)
        external
        override
        whenNotPaused
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        AxiomTypesV2.License storage license = s.licenses[_licenseId];

        if (license.licensor != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, license.licensor);
        }

        // Commercial terms are immutable after the first purchase.
        if (s.licensePurchaseCount[_licenseId] != 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        if (_validUntil != 0 && _validUntil <= block.timestamp) {
            revert AxiomTypesV2.LicenseExpired(_licenseId, _validUntil);
        }

        license.price = _price;
        license.validUntil = _validUntil;
        license.exclusive = _exclusive;
    }

    /**
     * @notice Deactivates a license (no new purchases allowed).
     * @dev Existing purchases remain valid until their expiration.
     * @param _licenseId The License ID to deactivate.
     */
    function deactivateLicense(uint256 _licenseId) external override whenNotPaused {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        AxiomTypesV2.License storage license = s.licenses[_licenseId];

        if (license.licensor != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, license.licensor);
        }

        license.active = false;

        emit LicenseDeactivated(_licenseId, msg.sender);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          LICENSE PURCHASE (NFT MINTING)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Purchases a license (mints License NFT to buyer).
     * @dev Payment is distributed according to royalty split configuration.
     * @param _licenseId The License template ID to purchase.
     * @param _duration The requested license duration in seconds.
     * @return tokenId The minted NFT token ID representing the license.
     */
    function purchaseLicense(uint256 _licenseId, uint40 _duration)
        external
        payable
        override
        nonReentrant
        whenNotPaused
        notBanned
        returns (uint256 tokenId)
    {
        return _purchaseLicense(_licenseId, msg.sender, _duration);
    }

    /**
     * @notice Purchases a license on behalf of another address (gift).
     * @dev Mints the license NFT directly to the recipient.
     * @param _licenseId The License template ID.
     * @param _recipient The address to receive the license NFT.
     * @param _duration The requested license duration.
     * @return tokenId The minted NFT token ID.
     */
    function purchaseLicenseFor(uint256 _licenseId, address _recipient, uint40 _duration)
        external
        payable
        override
        nonReentrant
        whenNotPaused
        notBanned
        returns (uint256 tokenId)
    {
        if (_recipient == address(0)) {
            revert AxiomTypesV2.ZeroAddress();
        }
        return _purchaseLicense(_licenseId, _recipient, _duration);
    }

    /**
     * @dev Internal logic for license purchase.
     *      CEI: ALL state changes (mint NFT, write purchase data, set exclusive flag)
     *      happen BEFORE _processPayment which makes external calls.
     *      This prevents ERC-777 tokensToSend reentrancy from bypassing the
     *      exclusive license check and minting duplicate NFTs.
     */
    function _purchaseLicense(uint256 _licenseId, address _recipient, uint40 _duration)
        internal
        returns (uint256 tokenId)
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        AxiomTypesV2.License storage license = s.licenses[_licenseId];

        // CHECKS
        if (!license.active) {
            revert AxiomTypesV2.LicenseNotFound(_licenseId);
        }

        if (_getActiveRecordIssuer(s, license.recordId) != license.licensor) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        if (license.exclusive && license.licensee != address(0)) {
            revert AxiomTypesV2.LicenseAlreadyPurchased(_licenseId);
        }

        if (license.validUntil > 0 && license.validUntil <= block.timestamp) {
            revert AxiomTypesV2.LicenseExpired(_licenseId, license.validUntil);
        }

        uint256 price = license.price;

        // EFFECTS: Write ALL state BEFORE any external calls
        // Initialize token counter if needed
        if (s.nextTokenId == 0) {
            s.nextTokenId = 1;
        }

        // Mint NFT (state-only, no external calls)
        tokenId = s.nextTokenId++;
        _mint(_recipient, tokenId);

        // Record purchase data
        uint40 expiresAt;
        if (_duration > 0) {
            uint256 requestedExpiry = block.timestamp + uint256(_duration);
            if (requestedExpiry > type(uint40).max) {
                revert AxiomTypesV2.OperationNotPermitted();
            }
            if (license.validUntil != 0 && requestedExpiry > license.validUntil) {
                revert AxiomTypesV2.LicenseExpired(_licenseId, license.validUntil);
            }
            expiresAt = uint40(requestedExpiry);
        } else {
            expiresAt = license.validUntil;
        }

        s.tokenLicenseData[tokenId] = AxiomTypesV2.LicensePurchase({
            licenseId: _licenseId,
            tokenId: tokenId,
            buyer: _recipient,
            pricePaid: price,
            purchasedAt: uint40(block.timestamp),
            expiresAt: expiresAt
        });
        s.licensePurchaseCount[_licenseId]++;

        // Mark exclusive license BEFORE payment interaction
        // This is the critical fix: if an ERC-777 hook re-enters purchaseLicense,
        // the exclusive check above will now correctly revert
        if (license.exclusive) {
            license.licensee = _recipient;
        }

        emit LicensePurchased(_licenseId, tokenId, _recipient, price);

        // INTERACTION: Process payment (external calls) LAST
        _processPayment(license.paymentToken, price, license.licensor, license.recordId);
    }

    /**
     * @dev Process payment for license purchase.
     *      CEI: This is called AFTER all state is written in _purchaseLicense.
     *      For ERC-20: safeTransferFrom is the external call (interaction).
     *      For ETH: .call is the external call (interaction).
     */
    function _processPayment(address _token, uint256 _amount, address _licensor, bytes32 _recordId) internal {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        if (_amount == 0) {
            if (msg.value != 0) {
                revert AxiomTypesV2.OperationNotPermitted();
            }
            return;
        }

        // Calculate splits
        uint256 protocolFee = (_amount * PROTOCOL_FEE_BPS) / BPS_DENOMINATOR;
        uint256 licensorAmount = _amount - protocolFee;

        if (_token == address(0)) {
            // ETH payment
            if (msg.value < _amount) {
                revert AxiomTypesV2.InsufficientFee(msg.value, _amount);
            }

            // INTERACTIONS: All external calls grouped together
            // Send to treasury
            address treasury = _licenseTreasury(s);
            if (protocolFee != 0) {
                (bool success1,) = payable(treasury).call{value: protocolFee}("");
                require(success1, "LicenseFacet: Treasury transfer failed");
            }

            // Check if there's a royalty split
            AxiomTypesV2.RoyaltySplit storage split = s.royaltySplits[_recordId];
            if (split.recipients.length > 0) {
                _distributeRoyaltiesETH(licensorAmount, split);
            } else {
                // Send all to licensor
                (bool success2,) = payable(_licensor).call{value: licensorAmount}("");
                require(success2, "LicenseFacet: Licensor transfer failed");
            }

            // Refund excess
            if (msg.value > _amount) {
                (bool success3,) = payable(msg.sender).call{value: msg.value - _amount}("");
                require(success3, "LicenseFacet: Refund failed");
            }
        } else {
            // ERC-20 payment
            if (msg.value != 0) {
                revert AxiomTypesV2.OperationNotPermitted();
            }
            IERC20 token = IERC20(_token);

            // Pull tokens from buyer
            uint256 balanceBefore = token.balanceOf(address(this));
            token.safeTransferFrom(msg.sender, address(this), _amount);
            if (token.balanceOf(address(this)) - balanceBefore != _amount) {
                revert AxiomTypesV2.OperationNotPermitted();
            }

            // Distribute: protocol fee
            address treasury = _licenseTreasury(s);
            if (protocolFee != 0) {
                token.safeTransfer(treasury, protocolFee);
            }

            // Distribute: licensor / royalty split
            AxiomTypesV2.RoyaltySplit storage split = s.royaltySplits[_recordId];
            if (split.recipients.length > 0) {
                _distributeRoyaltiesERC20(token, licensorAmount, split);
            } else {
                token.safeTransfer(_licensor, licensorAmount);
            }
        }
    }

    function _distributeRoyaltiesETH(uint256 _amount, AxiomTypesV2.RoyaltySplit storage _split) internal {
        uint256 distributed;
        for (uint256 i = 0; i < _split.recipients.length; i++) {
            uint256 share = i + 1 == _split.recipients.length
                ? _amount - distributed
                : (_amount * _split.shares[i]) / BPS_DENOMINATOR;
            distributed += share;
            if (share > 0) {
                (bool success,) = payable(_split.recipients[i]).call{value: share}("");
                require(success, "Royalty transfer failed");
            }
        }
    }

    function _distributeRoyaltiesERC20(IERC20 _token, uint256 _amount, AxiomTypesV2.RoyaltySplit storage _split)
        internal
    {
        uint256 distributed;
        for (uint256 i = 0; i < _split.recipients.length; i++) {
            uint256 share = i + 1 == _split.recipients.length
                ? _amount - distributed
                : (_amount * _split.shares[i]) / BPS_DENOMINATOR;
            distributed += share;
            if (share > 0) {
                _token.safeTransfer(_split.recipients[i], share);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ERC-721 CORE IMPLEMENTATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Returns the number of tokens owned by an address.
     * @param _owner The address to query.
     * @return The number of tokens owned.
     */
    function balanceOf(address _owner) external view returns (uint256) {
        require(_owner != address(0), "ERC721: balance query for zero address");
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.tokenBalance[_owner];
    }

    /**
     * @notice Returns the owner of a token.
     * @param _tokenId The Token ID to query.
     * @return The address of the owner.
     */
    function ownerOf(uint256 _tokenId) public view tokenExists(_tokenId) returns (address) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.tokenOwner[_tokenId];
    }

    /**
     * @notice Transfers a token from one address to another.
     * @dev Throws unless `msg.sender` is the current owner, an authorized operator, or the approved address for this token.
     *      nonReentrant: prevents state manipulation during concurrent operations.
     * @param _from The current owner of the token.
     * @param _to The new owner.
     * @param _tokenId The Token ID to transfer.
     */
    function transferFrom(address _from, address _to, uint256 _tokenId) external nonReentrant whenNotPaused {
        _transfer(_from, _to, _tokenId);
    }

    /**
     * @notice Safely transfers a token from one address to another.
     * @dev Checks for ERC721Receiver implementation on destination.
     *      nonReentrant: onERC721Received callback is an external call to untrusted code.
     * @param _from The current owner of the token.
     * @param _to The new owner.
     * @param _tokenId The Token ID to transfer.
     */
    function safeTransferFrom(address _from, address _to, uint256 _tokenId) external nonReentrant whenNotPaused {
        _safeTransfer(_from, _to, _tokenId, "");
    }

    /**
     * @notice Safely transfers a token with additional data.
     * @dev nonReentrant: onERC721Received is an external call to untrusted code.
     * @param _from The current owner of the token.
     * @param _to The new owner.
     * @param _tokenId The Token ID to transfer.
     * @param _data Additional data with no specified format, sent in call to `onERC721Received`.
     */
    function safeTransferFrom(address _from, address _to, uint256 _tokenId, bytes memory _data)
        public
        nonReentrant
        whenNotPaused
    {
        _safeTransfer(_from, _to, _tokenId, _data);
    }

    /**
     * @dev Internal safe transfer logic — separated from the public function
     *      so that the nonReentrant modifier is only on the external entry points.
     */
    function _safeTransfer(address _from, address _to, uint256 _tokenId, bytes memory _data) internal {
        _transfer(_from, _to, _tokenId);
        _checkOnERC721Received(_from, _to, _tokenId, _data);
    }

    /**
     * @notice Approves another address to transfer the given token ID.
     * @dev The zero address indicates there is no approved address.
     *      nonReentrant: defense-in-depth in shared Diamond storage.
     * @param _approved The address to be approved for the given token ID.
     * @param _tokenId The Token ID to approve.
     */
    function approve(address _approved, uint256 _tokenId) external nonReentrant whenNotPaused tokenExists(_tokenId) {
        address owner = ownerOf(_tokenId);
        require(_approved != owner, "ERC721: approval to current owner");
        require(
            msg.sender == owner || isApprovedForAll(owner, msg.sender),
            "ERC721: approve caller is not owner nor approved for all"
        );

        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.tokenApprovals[_tokenId] = _approved;

        emit Approval(owner, _approved, _tokenId);
    }

    /**
     * @notice Sets or unsets the approval of a given operator.
     * @dev An operator is allowed to transfer all tokens of the sender on their behalf.
     * @param _operator The operator to approve or remove.
     * @param _approved True to approve the operator, false to revoke.
     */
    function setApprovalForAll(address _operator, bool _approved) external whenNotPaused {
        require(_operator != msg.sender, "ERC721: approve to caller");

        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.operatorApprovals[msg.sender][_operator] = _approved;

        emit ApprovalForAll(msg.sender, _operator, _approved);
    }

    /**
     * @notice Returns the account approved for the given token ID.
     * @param _tokenId The Token ID to query.
     * @return The approved address for this token, or the zero address if none.
     */
    function getApproved(uint256 _tokenId) public view tokenExists(_tokenId) returns (address) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.tokenApprovals[_tokenId];
    }

    /**
     * @notice Returns if the `_operator` is allowed to manage all of the assets of `_owner`.
     * @param _owner The address that owns the tokens.
     * @param _operator The address that acts on behalf of the owner.
     * @return True if the operator is approved, false otherwise.
     */
    function isApprovedForAll(address _owner, address _operator) public view returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.operatorApprovals[_owner][_operator];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ERC-721 METADATA
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Returns the name of the token collection.
     * @return The name of the collection.
     */
    function name() external pure returns (string memory) {
        return "Axiom License";
    }

    /**
     * @notice Returns the symbol of the token collection.
     * @return The symbol of the collection.
     */
    function symbol() external pure returns (string memory) {
        return "AXLICENSE";
    }

    /**
     * @notice Returns the Uniform Resource Identifier (URI) for `_tokenId` token.
     * @param _tokenId The Token ID to query.
     * @return The metadata URI.
     */
    function tokenURI(uint256 _tokenId) external view tokenExists(_tokenId) returns (string memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.LicensePurchase storage purchase = s.tokenLicenseData[_tokenId];
        AxiomTypesV2.License storage license = s.licenses[purchase.licenseId];

        // Simple JSON metadata (in production, return IPFS URI)
        return string(
            abi.encodePacked(
                "data:application/json;base64,", Base64.encode(bytes(_encodeMetadata(_tokenId, purchase, license)))
            )
        );
    }

    function _encodeMetadata(
        uint256 _tokenId,
        AxiomTypesV2.LicensePurchase storage _purchase,
        AxiomTypesV2.License storage _license
    ) internal view returns (string memory) {
        // Simplified - in production use Base64 encoding library
        return string(
            abi.encodePacked(
                '{"name":"Axiom License #',
                _tokenId.toString(),
                '",',
                '"description":"License for content record",',
                '"attributes":[',
                '{"trait_type":"License Type","value":"',
                _getLicenseTypeName(_license.licenseType),
                '"},',
                '{"trait_type":"Royalty","value":"',
                uint256(_license.royaltyBps).toString(),
                '"}',
                "]}"
            )
        );
    }

    function _getLicenseTypeName(AxiomTypesV2.LicenseType _type) internal pure returns (string memory) {
        if (_type == AxiomTypesV2.LicenseType.CC0) return "CC0";
        if (_type == AxiomTypesV2.LicenseType.CC_BY) return "CC-BY";
        if (_type == AxiomTypesV2.LicenseType.CC_BY_SA) return "CC-BY-SA";
        if (_type == AxiomTypesV2.LicenseType.CC_BY_NC) return "CC-BY-NC";
        if (_type == AxiomTypesV2.LicenseType.CC_BY_NC_SA) return "CC-BY-NC-SA";
        if (_type == AxiomTypesV2.LicenseType.CC_BY_ND) return "CC-BY-ND";
        if (_type == AxiomTypesV2.LicenseType.CC_BY_NC_ND) return "CC-BY-NC-ND";
        if (_type == AxiomTypesV2.LicenseType.COMMERCIAL_SINGLE) return "Commercial Single";
        if (_type == AxiomTypesV2.LicenseType.COMMERCIAL_UNLIMITED) return "Commercial Unlimited";
        if (_type == AxiomTypesV2.LicenseType.EXCLUSIVE) return "Exclusive";
        return "Custom";
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    function _mint(address _to, uint256 _tokenId) internal {
        require(_to != address(0), "ERC721: mint to zero address");

        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        require(s.tokenOwner[_tokenId] == address(0), "ERC721: token already minted");

        s.tokenBalance[_to] += 1;
        s.tokenOwner[_tokenId] = _to;
        s.ownedLicenseTokenIndex[_tokenId] = s.ownedLicenseTokens[_to].length + 1;
        s.ownedLicenseTokens[_to].push(_tokenId);

        emit Transfer(address(0), _to, _tokenId);
    }

    function _transfer(address _from, address _to, uint256 _tokenId) internal {
        require(ownerOf(_tokenId) == _from, "ERC721: transfer from incorrect owner");
        require(_to != address(0), "ERC721: transfer to zero address");
        require(
            msg.sender == _from || isApprovedForAll(_from, msg.sender) || getApproved(_tokenId) == msg.sender,
            "ERC721: caller is not owner nor approved"
        );

        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        // Clear approvals
        delete s.tokenApprovals[_tokenId];

        // Update balances
        _removeOwnedToken(s, _from, _tokenId);
        s.tokenBalance[_from] -= 1;
        s.tokenBalance[_to] += 1;
        s.tokenOwner[_tokenId] = _to;
        AxiomTypesV2.License storage license = s.licenses[s.tokenLicenseData[_tokenId].licenseId];
        if (license.exclusive) license.licensee = _to;
        s.ownedLicenseTokenIndex[_tokenId] = s.ownedLicenseTokens[_to].length + 1;
        s.ownedLicenseTokens[_to].push(_tokenId);

        emit Transfer(_from, _to, _tokenId);
    }

    function _checkOnERC721Received(address _from, address _to, uint256 _tokenId, bytes memory _data) private {
        if (_to.code.length > 0) {
            try IERC721Receiver(_to).onERC721Received(msg.sender, _from, _tokenId, _data) returns (bytes4 retval) {
                require(retval == IERC721Receiver.onERC721Received.selector, "ERC721: transfer to non ERC721Receiver");
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ERC-2981 ROYALTY INFO
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Returns royalty payment information for secondary sales.
     * @dev ERC-2981 standard implementation.
     * @param _tokenId The License NFT token ID.
     * @param _salePrice The sale price of the NFT.
     * @return receiver The address to receive royalty payment.
     * @return royaltyAmount The amount of royalty to pay.
     */
    function royaltyInfo(uint256 _tokenId, uint256 _salePrice)
        external
        view
        override(IAxiomLicense)
        tokenExists(_tokenId)
        returns (address receiver, uint256 royaltyAmount)
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        AxiomTypesV2.LicensePurchase storage purchase = s.tokenLicenseData[_tokenId];
        AxiomTypesV2.License storage license = s.licenses[purchase.licenseId];

        receiver = license.licensor;
        royaltyAmount = (_salePrice * license.royaltyBps) / BPS_DENOMINATOR;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ROYALTY MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Sets the royalty distribution split for content.
     * @dev Shares must sum to 10000 (100%).
     * @param _recordId The content record ID.
     * @param _recipients The array of royalty recipient addresses.
     * @param _shares The array of share amounts in basis points.
     */
    function setRoyaltySplit(bytes32 _recordId, address[] calldata _recipients, uint16[] calldata _shares)
        external
        override
        whenNotPaused
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        address issuer = _getActiveRecordIssuer(s, _recordId);
        if (issuer != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, issuer);
        }

        if (_recipients.length != _shares.length) {
            revert AxiomTypesV2.ArrayLengthMismatch();
        }

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

        s.royaltySplits[_recordId] =
            AxiomTypesV2.RoyaltySplit({recipients: _recipients, shares: _shares, autoDistribute: true});

        emit RoyaltySplitUpdated(_recordId, _recipients, _shares);
    }

    /**
     * @notice Claims accumulated royalties for caller.
     * @dev Not implemented in v1 - royalties auto-distributed on purchase.
     * @param _recordId The content record ID (unused).
     * @return amount Always returns 0.
     */
    function claimRoyalties(bytes32 _recordId) external pure override returns (uint256) {
        // Not implemented - royalties auto-distributed on purchase
        return 0;
    }

    /**
     * @notice Claims royalties in a specific token.
     * @dev Not implemented in v1.
     * @param _recordId The content record ID (unused).
     * @param _token The token address (unused).
     * @return amount Always returns 0.
     */
    function claimRoyaltiesToken(bytes32 _recordId, address _token) external pure override returns (uint256) {
        // Not implemented - royalties auto-distributed on purchase
        return 0;
    }

    /**
     * @notice Gets pending royalties for an address.
     * @dev Not implemented in v1.
     * @param _recipient The address to check (unused).
     * @param _recordId The content record ID (unused).
     * @return pending Always returns 0.
     */
    function pendingRoyalties(address _recipient, bytes32 _recordId) external pure override returns (uint256) {
        // Not implemented - royalties auto-distributed on purchase
        return 0;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          SUBLICENSING (STUB)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Creates a sublicense from an existing license (stub).
     * @dev Not implemented in v1.
     * @return sublicenseId Reverts.
     */
    function createSublicense(uint256, uint256, uint40) external pure override returns (uint256) {
        revert AxiomTypesV2.OperationNotPermitted(); // Not implemented in v1
    }

    /**
     * @notice Purchases a sublicense (stub).
     * @dev Not implemented in v1.
     * @return tokenId Reverts.
     */
    function purchaseSublicense(uint256) external payable override returns (uint256) {
        revert AxiomTypesV2.OperationNotPermitted(); // Not implemented in v1
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          QUERY FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Retrieves license template information.
     * @param _licenseId The License template ID.
     * @return license The License struct.
     */
    function getLicense(uint256 _licenseId) external view override returns (AxiomTypesV2.License memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.licenses[_licenseId];
    }

    /**
     * @notice Retrieves all license IDs for a record.
     * @param _recordId The ID of the content record.
     * @return licenseIds An array of license IDs.
     */
    function getLicensesByRecord(bytes32 _recordId) external view override returns (uint256[] memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.recordLicenses[_recordId];
    }

    /**
     * @notice Retrieves the license NFT token IDs currently owned by an address.
     * @dev The owner index is updated on mint and transfer.
     * @return tokenIds License NFT token IDs owned by `_owner`.
     */
    function getLicensesByOwner(address _owner) external view override returns (uint256[] memory) {
        return AxiomStorage.getStorage().ownedLicenseTokens[_owner];
    }

    /**
     * @notice Checks if an address has a valid license for content.
     * @dev Current implementation checks for token balance > 0 (simplified).
     * @param _licensee The address to check.
     * @param _recordId The ID of the content record.
     * @return isValid True if the licensee holds a valid license.
     * @return licenseType The type of license held.
     */
    function hasValidLicense(address _licensee, bytes32 _recordId)
        external
        view
        override
        returns (bool isValid, AxiomTypesV2.LicenseType licenseType)
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        uint256[] storage tokenIds = s.ownedLicenseTokens[_licensee];
        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            AxiomTypesV2.LicensePurchase storage purchase = s.tokenLicenseData[tokenId];
            if (s.licenses[purchase.licenseId].recordId != _recordId) continue;
            if (purchase.expiresAt != 0 && purchase.expiresAt <= block.timestamp) continue;

            return (true, s.licenses[purchase.licenseId].licenseType);
        }

        return (false, AxiomTypesV2.LicenseType.NONE);
    }

    /**
     * @notice Checks if a specific license NFT is still valid.
     * @param _tokenId The License NFT token ID.
     * @return isValid True if the license is registered, active, and not expired.
     */
    function isLicenseValid(uint256 _tokenId) external view override returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        if (s.tokenOwner[_tokenId] == address(0)) {
            return false;
        }

        AxiomTypesV2.LicensePurchase storage purchase = s.tokenLicenseData[_tokenId];

        if (purchase.expiresAt > 0 && purchase.expiresAt <= block.timestamp) {
            return false;
        }

        return purchase.licenseId != 0;
    }

    /**
     * @notice Gets the royalty split configuration for content.
     * @param _recordId The content record ID.
     * @return split The RoyaltySplit struct.
     */
    function getRoyaltySplit(bytes32 _recordId) external view override returns (AxiomTypesV2.RoyaltySplit memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.royaltySplits[_recordId];
    }

    /**
     * @notice Sets geographic restrictions for a license.
     * @dev Restrictions are stored as IPFS URI.
     * @param _licenseId The License ID to update.
     * @param _restrictionsURI The new restrictions IPFS URI.
     */
    function setTerritoryRestrictions(uint256 _licenseId, string calldata _restrictionsURI)
        external
        override
        whenNotPaused
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        AxiomTypesV2.License storage license = s.licenses[_licenseId];

        if (license.licensor != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, license.licensor);
        }

        if (s.licensePurchaseCount[_licenseId] != 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        license.territoryRestrictions = _restrictionsURI;
    }

    function _getActiveRecordIssuer(AxiomStorage.Storage storage s, bytes32 _recordId)
        internal
        view
        returns (address issuer)
    {
        if (AxiomStorage.recordExistsV2(_recordId)) {
            AxiomTypesV2.AxiomRecord storage recordV2 = s.recordsV2[_recordId];
            if (recordV2.status != AxiomTypesV2.ContentStatus.ACTIVE) {
                revert AxiomTypesV2.InvalidContentStatus(_recordId, recordV2.status);
            }
            return recordV2.issuer;
        }
        if (AxiomStorage.recordExists(_recordId)) {
            AxiomTypes.AxiomRecord storage recordV1 = s.records[_recordId];
            if (recordV1.status != AxiomTypes.ContentStatus.ACTIVE) {
                revert AxiomTypesV2.OperationNotPermitted();
            }
            return recordV1.issuer;
        }
        revert AxiomTypesV2.ContentNotFound(_recordId);
    }

    function _removeOwnedToken(AxiomStorage.Storage storage s, address _owner, uint256 _tokenId) internal {
        uint256 indexPlusOne = s.ownedLicenseTokenIndex[_tokenId];
        require(indexPlusOne != 0, "ERC721: owner enumeration missing");
        uint256 index = indexPlusOne - 1;
        uint256 lastIndex = s.ownedLicenseTokens[_owner].length - 1;
        if (index != lastIndex) {
            uint256 lastTokenId = s.ownedLicenseTokens[_owner][lastIndex];
            s.ownedLicenseTokens[_owner][index] = lastTokenId;
            s.ownedLicenseTokenIndex[lastTokenId] = index + 1;
        }
        s.ownedLicenseTokens[_owner].pop();
        delete s.ownedLicenseTokenIndex[_tokenId];
    }

    function _licenseTreasury(AxiomStorage.Storage storage s) internal view returns (address treasury) {
        treasury = s.licenseTreasury != address(0) ? s.licenseTreasury : s.treasuryWallet;
        if (treasury == address(0)) {
            revert AxiomTypesV2.ZeroAddress();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ERC-165 SUPPORT
    // ═══════════════════════════════════════════════════════════════════════════

    function supportsInterface(bytes4 interfaceId) public pure override returns (bool) {
        return interfaceId == INTERFACE_ID_ERC721 || interfaceId == INTERFACE_ID_ERC721_METADATA
            || interfaceId == INTERFACE_ID_ERC2981 || interfaceId == type(IERC165).interfaceId;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          EVENTS (ERC-721)
    // ═══════════════════════════════════════════════════════════════════════════

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event LicenseTreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);

    // Required for receiving ETH
    receive() external payable {}
}

// IERC721Receiver interface
interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}
