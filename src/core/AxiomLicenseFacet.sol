// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC2981} from "@openzeppelin/contracts/interfaces/IERC2981.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";
import {IAxiomLicense} from "../interfaces/IAxiomLicense.sol";

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

    // ═══════════════════════════════════════════════════════════════════════════
    //                          LICENSE TEMPLATE MANAGEMENT
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
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Validate royalty
        if (_royaltyBps > BPS_DENOMINATOR) {
            revert AxiomTypesV2.InvalidRoyaltySplit(_royaltyBps);
        }
        
        // Custom type requires terms URI
        if (_licenseType == AxiomTypesV2.LicenseType.CUSTOM && bytes(_customTermsURI).length == 0) {
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

    /// @inheritdoc IAxiomLicense
    function updateLicense(
        uint256 _licenseId,
        uint256 _price,
        uint40 _validUntil,
        bool _exclusive
    ) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        AxiomTypesV2.License storage license = s.licenses[_licenseId];
        
        if (license.licensor != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, license.licensor);
        }
        
        // Can only update if no purchases yet
        if (license.exclusive && license.licensee != address(0)) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        license.price = _price;
        license.validUntil = _validUntil;
        license.exclusive = _exclusive;
    }

    /// @inheritdoc IAxiomLicense
    function deactivateLicense(uint256 _licenseId) external override {
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
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
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

        // Initialize token counter if needed
        if (s.nextTokenId == 0) {
            s.nextTokenId = 1;
        }

        // Mint NFT
        tokenId = s.nextTokenId++;
        _mint(_recipient, tokenId);

        // Record purchase
        uint40 expiresAt = _duration > 0 ? uint40(block.timestamp) + _duration : license.validUntil;
        
        s.tokenLicenseData[tokenId] = AxiomTypesV2.LicensePurchase({
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
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
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
            address treasury = s.licenseTreasury != address(0) ? s.licenseTreasury : s.treasuryWallet;
            (bool success1,) = payable(treasury).call{value: protocolFee}("");
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
            address treasury = s.licenseTreasury != address(0) ? s.licenseTreasury : s.treasuryWallet;
            token.safeTransfer(treasury, protocolFee);

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
    //                          ERC-721 CORE IMPLEMENTATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Returns the number of tokens owned by an address
     */
    function balanceOf(address _owner) external view returns (uint256) {
        require(_owner != address(0), "ERC721: balance query for zero address");
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.tokenBalance[_owner];
    }

    /**
     * @notice Returns the owner of a token
     */
    function ownerOf(uint256 _tokenId) public view tokenExists(_tokenId) returns (address) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.tokenOwner[_tokenId];
    }

    /**
     * @notice Transfer token from one address to another
     */
    function transferFrom(
        address _from,
        address _to,
        uint256 _tokenId
    ) external {
        _transfer(_from, _to, _tokenId);
    }

    /**
     * @notice Safely transfer token from one address to another
     */
    function safeTransferFrom(
        address _from,
        address _to,
        uint256 _tokenId
    ) external {
        safeTransferFrom(_from, _to, _tokenId, "");
    }

    /**
     * @notice Safely transfer token with data
     */
    function safeTransferFrom(
        address _from,
        address _to,
        uint256 _tokenId,
        bytes memory _data
    ) public {
        _transfer(_from, _to, _tokenId);
        _checkOnERC721Received(_from, _to, _tokenId, _data);
    }

    /**
     * @notice Approve address to transfer token
     */
    function approve(address _approved, uint256 _tokenId) external tokenExists(_tokenId) {
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
     * @notice Set approval for all tokens
     */
    function setApprovalForAll(address _operator, bool _approved) external {
        require(_operator != msg.sender, "ERC721: approve to caller");
        
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.operatorApprovals[msg.sender][_operator] = _approved;
        
        emit ApprovalForAll(msg.sender, _operator, _approved);
    }

    /**
     * @notice Get approved address for token
     */
    function getApproved(uint256 _tokenId) public view tokenExists(_tokenId) returns (address) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.tokenApprovals[_tokenId];
    }

    /**
     * @notice Check if operator is approved for all tokens
     */
    function isApprovedForAll(address _owner, address _operator) public view returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.operatorApprovals[_owner][_operator];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ERC-721 METADATA
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice NFT collection name
     */
    function name() external pure returns (string memory) {
        return "Axiom License";
    }

    /**
     * @notice NFT collection symbol
     */
    function symbol() external pure returns (string memory) {
        return "AXLICENSE";
    }

    /**
     * @notice Generate token metadata URI
     */
    function tokenURI(uint256 _tokenId) external view tokenExists(_tokenId) returns (string memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.LicensePurchase storage purchase = s.tokenLicenseData[_tokenId];
        AxiomTypesV2.License storage license = s.licenses[purchase.licenseId];
        
        // Simple JSON metadata (in production, return IPFS URI)
        return string(abi.encodePacked(
            "data:application/json;base64,",
            _encodeMetadata(_tokenId, purchase, license)
        ));
    }

    function _encodeMetadata(
        uint256 _tokenId,
        AxiomTypesV2.LicensePurchase storage _purchase,
        AxiomTypesV2.License storage _license
    ) internal view returns (string memory) {
        // Simplified - in production use Base64 encoding library
        return string(abi.encodePacked(
            '{"name":"Axiom License #', _tokenId.toString(), '",',
            '"description":"License for content record",',
            '"attributes":[',
            '{"trait_type":"License Type","value":"', _getLicenseTypeName(_license.licenseType), '"},',
            '{"trait_type":"Royalty","value":"', uint256(_license.royaltyBps).toString(), '"}',
            ']}'
        ));
    }

    function _getLicenseTypeName(AxiomTypesV2.LicenseType _type) internal pure returns (string memory) {
        if (_type == AxiomTypesV2.LicenseType.CC0) return "CC0";
        if (_type == AxiomTypesV2.LicenseType.CC_BY) return "CC-BY";
        if (_type == AxiomTypesV2.LicenseType.CC_BY_SA) return "CC-BY-SA";
        if (_type == AxiomTypesV2.LicenseType.CC_BY_NC) return "CC-BY-NC";
        if (_type == AxiomTypesV2.LicenseType.COMMERCIAL_SINGLE) return "Commercial Single";
        if (_type == AxiomTypesV2.LicenseType.COMMERCIAL_UNLIMITED) return "Commercial Unlimited";
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

        emit Transfer(address(0), _to, _tokenId);
    }

    function _transfer(
        address _from,
        address _to,
        uint256 _tokenId
    ) internal {
        require(ownerOf(_tokenId) == _from, "ERC721: transfer from incorrect owner");
        require(_to != address(0), "ERC721: transfer to zero address");
        require(
            msg.sender == _from || 
            isApprovedForAll(_from, msg.sender) || 
            getApproved(_tokenId) == msg.sender,
            "ERC721: caller is not owner nor approved"
        );

        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        // Clear approvals
        delete s.tokenApprovals[_tokenId];

        // Update balances
        s.tokenBalance[_from] -= 1;
        s.tokenBalance[_to] += 1;
        s.tokenOwner[_tokenId] = _to;

        emit Transfer(_from, _to, _tokenId);
    }

    function _checkOnERC721Received(
        address _from,
        address _to,
        uint256 _tokenId,
        bytes memory _data
    ) private {
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

    /// @inheritdoc IAxiomLicense
    function royaltyInfo(uint256 _tokenId, uint256 _salePrice)
        external view override(IAxiomLicense) tokenExists(_tokenId)
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

    /// @inheritdoc IAxiomLicense
    function setRoyaltySplit(
        bytes32 _recordId,
        address[] calldata _recipients,
        uint16[] calldata _shares
    ) external override {
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

        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        s.royaltySplits[_recordId] = AxiomTypesV2.RoyaltySplit({
            recipients: _recipients,
            shares: _shares,
            autoDistribute: true
        });

        emit RoyaltySplitUpdated(_recordId, _recipients, _shares);
    }

    /// @inheritdoc IAxiomLicense
    function claimRoyalties(bytes32) external pure override returns (uint256) {
        // Not implemented - royalties auto-distributed on purchase
        return 0;
    }

    /// @inheritdoc IAxiomLicense
    function claimRoyaltiesToken(bytes32, address) external pure override returns (uint256) {
        // Not implemented - royalties auto-distributed on purchase
        return 0;
    }

    /// @inheritdoc IAxiomLicense
    function pendingRoyalties(address, bytes32) external pure override returns (uint256) {
        // Not implemented - royalties auto-distributed on purchase
        return 0;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          SUBLICENSING (STUB)
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomLicense
    function createSublicense(uint256, uint256, uint40) external pure override returns (uint256) {
        revert AxiomTypesV2.OperationNotPermitted(); // Not implemented in v1
    }

    /// @inheritdoc IAxiomLicense
    function purchaseSublicense(uint256) external payable override returns (uint256) {
        revert AxiomTypesV2.OperationNotPermitted(); // Not implemented in v1
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          QUERY FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomLicense
    function getLicense(uint256 _licenseId) 
        external view override 
        returns (AxiomTypesV2.License memory) 
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.licenses[_licenseId];
    }

    /// @inheritdoc IAxiomLicense
    function getLicensesByRecord(bytes32 _recordId) 
        external view override 
        returns (uint256[] memory) 
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.recordLicenses[_recordId];
    }

    /// @inheritdoc IAxiomLicense
    function getLicensesByOwner(address) 
        external pure override 
        returns (uint256[] memory) 
    {
        // Would require enumeration - not implemented for gas efficiency
        revert AxiomTypesV2.OperationNotPermitted();
    }

    /// @inheritdoc IAxiomLicense
    function hasValidLicense(address _licensee, bytes32 _recordId) 
        external view override 
        returns (bool isValid, AxiomTypesV2.LicenseType licenseType) 
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Check owned tokens (simplified - would need enumeration for full implementation)
        uint256 balance = s.tokenBalance[_licensee];
        if (balance == 0) {
            return (false, AxiomTypesV2.LicenseType.NONE);
        }
        
        // In production, would iterate through owned tokens
        // For now, return basic check
        return (false, AxiomTypesV2.LicenseType.NONE);
    }

    /// @inheritdoc IAxiomLicense
    function isLicenseValid(uint256 _tokenId) external view override returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (s.tokenOwner[_tokenId] == address(0)) {
            return false;
        }
        
        AxiomTypesV2.LicensePurchase storage purchase = s.tokenLicenseData[_tokenId];
        
        if (purchase.expiresAt > 0 && purchase.expiresAt < block.timestamp) {
            return false;
        }
        
        AxiomTypesV2.License storage license = s.licenses[purchase.licenseId];
        return license.active;
    }

    /// @inheritdoc IAxiomLicense
    function getRoyaltySplit(bytes32 _recordId) 
        external view override 
        returns (AxiomTypesV2.RoyaltySplit memory) 
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.royaltySplits[_recordId];
    }

    /// @inheritdoc IAxiomLicense
    function setTerritoryRestrictions(uint256 _licenseId, string calldata _restrictionsURI) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        AxiomTypesV2.License storage license = s.licenses[_licenseId];
        
        if (license.licensor != msg.sender) {
            revert AxiomTypesV2.NotLicensor(msg.sender, license.licensor);
        }

        license.territoryRestrictions = _restrictionsURI;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ERC-165 SUPPORT
    // ═══════════════════════════════════════════════════════════════════════════

    function supportsInterface(bytes4 interfaceId) public pure override returns (bool) {
        return
            interfaceId == INTERFACE_ID_ERC721 ||
            interfaceId == INTERFACE_ID_ERC721_METADATA ||
            interfaceId == INTERFACE_ID_ERC2981 ||
            interfaceId == type(IERC165).interfaceId;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          EVENTS (ERC-721)
    // ═══════════════════════════════════════════════════════════════════════════

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    // Required for receiving ETH
    receive() external payable {}
}

// IERC721Receiver interface
interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}
