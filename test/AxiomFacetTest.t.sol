// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {AxiomRouter} from "../src/AxiomRouter.sol";
import {AxiomRegistry} from "../src/core/AxiomRegistry.sol";
import {AxiomTreasury} from "../src/core/AxiomTreasury.sol";
import {AxiomIdentity} from "../src/core/AxiomIdentity.sol";
import {AxiomAccess} from "../src/access/AxiomAccess.sol";
import {AxiomDIDRegistry} from "../src/core/AxiomDIDRegistry.sol";
import {AxiomLicenseFacet} from "../src/core/AxiomLicenseFacet.sol";
import {AxiomDisputeFacet} from "../src/core/AxiomDisputeFacet.sol";
import {AxiomPrivacyFacet} from "../src/core/AxiomPrivacyFacet.sol";
import {AxiomFacets} from "../src/interfaces/AxiomFacets.sol";
import {AxiomTypesV2} from "../src/libraries/AxiomTypesV2.sol";
import {AxiomSelectorManifest} from "../script/AxiomSelectorManifest.sol";

// ─── Mock ERC-20 Token for Payment & Staking Tests ────────────────────────
contract MockERC20 is IERC20 {
    string public name = "Mock Token";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

// ─── Mock Arbitrator for escalation tests ──────────────────────────────
contract MockArbitrator {
    uint256 public nextDisputeId = 100;
    uint256 public fee = 0.1 ether;
    address public axiomProxy;

    function setProxy(address _proxy) external {
        axiomProxy = _proxy;
    }

    function arbitrationCost(bytes calldata) external view returns (uint256) {
        return fee;
    }

    function createDispute(uint256, bytes calldata) external payable returns (uint256) {
        return nextDisputeId++;
    }

    function appeal(uint256, bytes calldata) external payable {}

    function appealCost(uint256, bytes calldata) external pure returns (uint256) {
        return 0;
    }

    function appealPeriod(uint256) external pure returns (uint256, uint256) {
        return (0, 0);
    }

    // Called by the proxy to rule on a dispute
    function callRule(uint256 _externalId, uint256 _ruling) external {
        // Call rule on the axiom proxy as the arbitrator
        (bool ok,) = axiomProxy.call(abi.encodeWithSignature("rule(uint256,uint256)", _externalId, _ruling));
        require(ok, "rule failed");
    }
}

/**
 * @title AxiomFacetTest
 * @notice Comprehensive facet-level tests for DID, License, and Dispute facets
 * @dev Targets >80% line coverage on each facet
 */
contract AxiomFacetTest is Test {
    AxiomRouter public router;
    AxiomFacets public diamond; // Cast of router proxy
    MockERC20 public mockToken;

    address public admin = address(this);
    address public treasury = address(0xBEEF);
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);
    address public charlie = address(0xC);
    address public verifier = address(0xFE);
    MockArbitrator public mockArbitrator;

    bytes32 constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 constant DEFAULT_ADMIN_ROLE = 0x00;

    // ═══════════════════════════════════════════════════════════════════════
    //                             SETUP
    // ═══════════════════════════════════════════════════════════════════════

    function setUp() public {
        // Deploy mock token and arbitrator
        mockToken = new MockERC20();
        mockToken.mint(alice, 1000 ether);
        mockToken.mint(bob, 1000 ether);
        mockArbitrator = new MockArbitrator();

        // Deploy Router proxy
        AxiomRouter impl = new AxiomRouter();
        bytes memory initData = abi.encodeWithSelector(AxiomRouter.initialize.selector, admin, treasury);
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        router = AxiomRouter(payable(address(proxy)));
        diamond = AxiomFacets(address(router));

        // Deploy facets
        AxiomRegistry regFacet = new AxiomRegistry();
        AxiomTreasury treFacet = new AxiomTreasury();
        AxiomIdentity idFacet = new AxiomIdentity();
        AxiomAccess acFacet = new AxiomAccess();
        AxiomDIDRegistry didFacet = new AxiomDIDRegistry();
        AxiomLicenseFacet licFacet = new AxiomLicenseFacet();
        AxiomDisputeFacet disFacet = new AxiomDisputeFacet();
        AxiomPrivacyFacet priFacet = new AxiomPrivacyFacet();

        router.addFacetSelectors(address(regFacet), AxiomSelectorManifest.registrySelectors());
        router.addFacetSelectors(address(treFacet), AxiomSelectorManifest.treasurySelectors());
        router.addFacetSelectors(address(idFacet), AxiomSelectorManifest.identitySelectors());
        router.addFacetSelectors(address(acFacet), AxiomSelectorManifest.accessSelectors());
        router.addFacetSelectors(address(didFacet), AxiomSelectorManifest.didSelectors());
        router.addFacetSelectors(address(licFacet), AxiomSelectorManifest.licenseSelectors());
        router.addFacetSelectors(address(disFacet), AxiomSelectorManifest.disputeSelectors());
        router.addFacetSelectors(address(priFacet), AxiomSelectorManifest.privacySelectors());

        // Grant VERIFIER_ROLE to verifier
        router.grantRole(VERIFIER_ROLE, verifier);

        // Fund test accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(charlie, 100 ether);

        // Configure disputes through production admin entry points.
        diamond.configureStakeConfig(_stakeConfig(address(0)));

        // Approve mock arbitrator through the production admin entry point.
        mockArbitrator.setProxy(address(diamond));
        diamond.setArbitrator(address(mockArbitrator), true);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                        HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    function _registerContent(address user) internal returns (bytes32) {
        bytes32 hash = keccak256(abi.encodePacked("content", user, block.timestamp));
        vm.prank(user);
        return diamond.register{value: 0.01 ether}(hash, "ipfs://metadata");
    }

    function _stakeConfig(address stakeToken) internal pure returns (AxiomTypesV2.StakeConfig memory) {
        return AxiomTypesV2.StakeConfig({
            minStakeAmount: 0.1 ether,
            minAppealStake: 0.2 ether,
            stakeToken: stakeToken,
            protocolFeeBps: 500,
            rewardBps: 0,
            slashBps: 0,
            responsePeriod: 3 days,
            evidencePeriod: 7 days,
            appealPeriod: 5 days
        });
    }

    function _registerDID(address user, string memory did) internal {
        vm.prank(user);
        diamond.registerDID(did, keccak256(bytes(did)), "jwk-key");
    }

    function _createLicenseETH(bytes32 recordId, address licensor, uint256 price) internal returns (uint256) {
        vm.prank(licensor);
        return diamond.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.CC_BY,
            price,
            address(0), // ETH
            500, // 5% royalty
            0, // no expiry
            false, // non-exclusive
            false, // non-sublicensable
            ""
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                      DID FACET TESTS (15 tests)
    // ═══════════════════════════════════════════════════════════════════════

    function test_DID_RegisterHappyPath() public {
        vm.prank(alice);
        diamond.registerDID("did:axiom:alice", keccak256("doc1"), "jwk-alice");

        assertTrue(diamond.hasDID(alice));
        assertTrue(diamond.isDIDActive(alice));
        assertEq(diamond.getDIDString(alice), "did:axiom:alice");
    }

    function test_DID_RegisterDuplicate_Reverts() public {
        _registerDID(alice, "did:axiom:alice");

        vm.prank(alice);
        vm.expectRevert();
        diamond.registerDID("did:axiom:alice2", keccak256("doc2"), "jwk2");
    }

    function test_DID_RegisterEmptyDID_Reverts() public {
        vm.prank(alice);
        vm.expectRevert();
        diamond.registerDID("", keccak256("doc"), "jwk");
    }

    function test_DID_RegisterZeroHash_Reverts() public {
        vm.prank(alice);
        vm.expectRevert();
        diamond.registerDID("did:axiom:alice", bytes32(0), "jwk");
    }

    function test_DID_UpdateDocument() public {
        _registerDID(alice, "did:axiom:alice");

        bytes32 newHash = keccak256("updated-doc");
        vm.prank(alice);
        diamond.updateDIDDocument(newHash);

        AxiomTypesV2.DIDIdentity memory id = diamond.getIdentity(alice);
        assertEq(id.didDocumentHash, newHash);
    }

    function test_DID_SetServiceEndpoint() public {
        _registerDID(alice, "did:axiom:alice");

        vm.prank(alice);
        diamond.setServiceEndpoint("https://alice.axiom.io");

        AxiomTypesV2.DIDIdentity memory id = diamond.getIdentity(alice);
        assertEq(id.serviceEndpoint, "https://alice.axiom.io");
    }

    function test_DID_RevokeDID() public {
        _registerDID(alice, "did:axiom:alice");

        vm.prank(alice);
        diamond.revokeDID();

        assertFalse(diamond.isDIDActive(alice));
        assertTrue(diamond.hasDID(alice)); // still exists, just inactive
    }

    function test_DID_AddDelegate() public {
        _registerDID(alice, "did:axiom:alice");
        bytes32 sigAuth = keccak256("sigAuth");

        vm.prank(alice);
        diamond.addDelegate(bob, sigAuth, 365 days);

        assertTrue(diamond.validDelegate(alice, sigAuth, bob));
    }

    function test_DID_AddDelegate_ZeroAddress_Reverts() public {
        _registerDID(alice, "did:axiom:alice");

        vm.prank(alice);
        vm.expectRevert();
        diamond.addDelegate(address(0), keccak256("sigAuth"), 365 days);
    }

    function test_DID_RevokeDelegate() public {
        _registerDID(alice, "did:axiom:alice");
        bytes32 sigAuth = keccak256("sigAuth");

        vm.prank(alice);
        diamond.addDelegate(bob, sigAuth, 365 days);
        assertTrue(diamond.validDelegate(alice, sigAuth, bob));

        vm.prank(alice);
        diamond.revokeDelegate(bob, sigAuth);
        assertFalse(diamond.validDelegate(alice, sigAuth, bob));
    }

    function test_DID_GetDelegates() public {
        _registerDID(alice, "did:axiom:alice");
        bytes32 sigAuth = keccak256("sigAuth");

        vm.prank(alice);
        diamond.addDelegate(bob, sigAuth, 365 days);

        AxiomTypesV2.DIDDelegate[] memory dels = diamond.getDelegates(alice);
        assertEq(dels.length, 1);
        assertEq(dels[0].delegate, bob);
    }

    function test_DID_SetVerificationLevel_AccessControl() public {
        _registerDID(alice, "did:axiom:alice");

        // Non-verifier should fail
        vm.prank(bob);
        vm.expectRevert();
        diamond.setVerificationLevel(alice, AxiomTypesV2.VerificationLevel.BASIC);

        // Verifier should succeed
        vm.prank(verifier);
        diamond.setVerificationLevel(alice, AxiomTypesV2.VerificationLevel.BASIC);

        assertEq(uint8(diamond.getVerificationLevel(alice)), uint8(AxiomTypesV2.VerificationLevel.BASIC));
    }

    function test_DID_MeetsVerificationLevel() public {
        _registerDID(alice, "did:axiom:alice");

        vm.prank(verifier);
        diamond.setVerificationLevel(alice, AxiomTypesV2.VerificationLevel.ENTERPRISE);

        assertTrue(diamond.meetsVerificationLevel(alice, AxiomTypesV2.VerificationLevel.BASIC));
        assertTrue(diamond.meetsVerificationLevel(alice, AxiomTypesV2.VerificationLevel.ENTERPRISE));
        assertFalse(diamond.meetsVerificationLevel(bob, AxiomTypesV2.VerificationLevel.BASIC)); // no DID
    }

    function test_DID_ResolveDID() public {
        _registerDID(alice, "did:axiom:alice");

        AxiomTypesV2.DIDIdentity memory id = diamond.resolveDID("did:axiom:alice");
        assertEq(id.did, "did:axiom:alice");
        assertTrue(id.isActive);
    }

    function test_DID_SetAttribute_And_Revoke() public {
        _registerDID(alice, "did:axiom:alice");
        bytes32 attrName = keccak256("email");
        bytes memory attrValue = bytes("alice@axiom.io");

        vm.prank(alice);
        diamond.setAttribute(attrName, attrValue, 365 days);

        // Revoke
        vm.prank(alice);
        diamond.revokeAttribute(attrName, attrValue);
    }

    function test_DID_VerifySignature() public {
        uint256 pk = 0xA11CE;
        address signer = vm.addr(pk);

        vm.prank(signer);
        diamond.registerDID("did:axiom:signer", keccak256("doc-signer"), "jwk-signer");

        // verifySignature internally wraps hash with toEthSignedMessageHash,
        // so we sign the eth-prefixed version and pass the raw hash
        bytes32 msgHash = keccak256("hello");
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(pk, ethHash);

        (bool valid, address recovered) = diamond.verifySignature(signer, msgHash, abi.encodePacked(r, s_, v));
        assertTrue(valid);
        assertEq(recovered, signer);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                    LICENSE FACET TESTS (20 tests)
    // ═══════════════════════════════════════════════════════════════════════

    function test_License_CreateHappyPath() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        uint256 licenseId = diamond.createLicense(
            recordId, AxiomTypesV2.LicenseType.CC_BY, 1 ether, address(0), 500, 0, false, false, ""
        );

        assertEq(licenseId, 1);
        AxiomTypesV2.License memory lic = diamond.getLicense(licenseId);
        assertEq(lic.licensor, alice);
        assertTrue(lic.active);
        assertEq(lic.price, 1 ether);
    }

    function test_License_CreateInvalidRoyalty_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        vm.expectRevert();
        diamond.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.CC_BY,
            1 ether,
            address(0),
            10001,
            0,
            false,
            false,
            "" // >10000 bps
        );
    }

    function test_License_UpdateLicense() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(alice);
        diamond.updateLicense(licenseId, 2 ether, 0, true);

        AxiomTypesV2.License memory lic = diamond.getLicense(licenseId);
        assertEq(lic.price, 2 ether);
        assertTrue(lic.exclusive);
    }

    function test_License_UpdateNotLicensor_Reverts() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        vm.expectRevert();
        diamond.updateLicense(licenseId, 2 ether, 0, true);
    }

    function test_License_DeactivateLicense() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(alice);
        diamond.deactivateLicense(licenseId);

        AxiomTypesV2.License memory lic = diamond.getLicense(licenseId);
        assertFalse(lic.active);
    }

    function test_License_PurchaseETH() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        assertEq(diamond.ownerOf(tokenId), bob);
        assertEq(diamond.balanceOf(bob), 1);
    }

    function test_License_PurchaseInactive_Reverts() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(alice);
        diamond.deactivateLicense(licenseId);

        vm.prank(bob);
        vm.expectRevert();
        diamond.purchaseLicense{value: 1 ether}(licenseId, 0);
    }

    function test_License_PurchaseFor() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicenseFor{value: 1 ether}(licenseId, charlie, 0);

        assertEq(diamond.ownerOf(tokenId), charlie);
    }

    function test_License_PurchaseForZeroAddress_Reverts() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        vm.expectRevert();
        diamond.purchaseLicenseFor{value: 1 ether}(licenseId, address(0), 0);
    }

    function test_License_ExclusiveDoublePurchase_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        uint256 licenseId = diamond.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.CC_BY,
            1 ether,
            address(0),
            500,
            0,
            true,
            false,
            "" // exclusive
        );

        vm.prank(bob);
        diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        vm.prank(charlie);
        vm.expectRevert();
        diamond.purchaseLicense{value: 1 ether}(licenseId, 0);
    }

    function test_License_TransferFrom() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        vm.prank(bob);
        diamond.transferFrom(bob, charlie, tokenId);

        assertEq(diamond.ownerOf(tokenId), charlie);
        assertEq(diamond.balanceOf(bob), 0);
        assertEq(diamond.balanceOf(charlie), 1);
    }

    function test_License_Approve_And_TransferFrom() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        vm.prank(bob);
        diamond.approve(charlie, tokenId);
        assertEq(diamond.getApproved(tokenId), charlie);

        vm.prank(charlie);
        diamond.transferFrom(bob, charlie, tokenId);
        assertEq(diamond.ownerOf(tokenId), charlie);
    }

    function test_License_SetApprovalForAll() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        vm.prank(bob);
        diamond.setApprovalForAll(charlie, true);
        assertTrue(diamond.isApprovedForAll(bob, charlie));

        vm.prank(charlie);
        diamond.transferFrom(bob, charlie, tokenId);
        assertEq(diamond.ownerOf(tokenId), charlie);
    }

    function test_License_NameAndSymbol() public view {
        assertEq(diamond.name(), "Axiom License");
        assertEq(diamond.symbol(), "AXLICENSE");
    }

    function test_License_TokenURI() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        string memory uri = diamond.tokenURI(tokenId);
        assertTrue(bytes(uri).length > 0);
    }

    function test_License_RoyaltyInfo() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        (address receiver, uint256 royalty) = diamond.royaltyInfo(tokenId, 10 ether);
        assertEq(receiver, alice);
        assertEq(royalty, 0.5 ether); // 500 bps = 5%
    }

    function test_License_SetRoyaltySplit() public {
        bytes32 recordId = _registerContent(alice);

        address[] memory recipients = new address[](2);
        recipients[0] = alice;
        recipients[1] = bob;
        uint16[] memory shares = new uint16[](2);
        shares[0] = 7000;
        shares[1] = 3000;

        vm.prank(alice);
        diamond.setRoyaltySplit(recordId, recipients, shares);

        AxiomTypesV2.RoyaltySplit memory split = diamond.getRoyaltySplit(recordId);
        assertEq(split.recipients.length, 2);
        assertEq(split.shares[0], 7000);
    }

    function test_License_SetRoyaltySplit_InvalidTotal_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        address[] memory recipients = new address[](1);
        recipients[0] = alice;
        uint16[] memory shares = new uint16[](1);
        shares[0] = 5000; // != 10000

        vm.prank(alice);
        vm.expectRevert();
        diamond.setRoyaltySplit(recordId, recipients, shares);
    }

    function test_License_SupportsInterface() public {
        // Note: The Router inherits AccessControlUpgradeable which has its own
        // supportsInterface. This means the Router handles supportsInterface
        // directly and never delegates to the LicenseFacet.
        // The Router's supportsInterface returns true for ERC165 and AccessControl
        // but false for ERC721 — this is expected Diamond behavior.
        (bool ok, bytes memory data) =
            address(diamond)
                .call(
                    abi.encodeWithSignature("supportsInterface(bytes4)", bytes4(0x01ffc9a7)) // ERC165
                );
        assertTrue(ok);
        // Router itself supports ERC-165
        assertTrue(abi.decode(data, (bool)));
    }

    function test_License_IsLicenseValid() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        (bool ok, bytes memory data) =
            address(diamond).call(abi.encodeWithSignature("isLicenseValid(uint256)", tokenId));
        assertTrue(ok);
        assertTrue(abi.decode(data, (bool)));
    }

    function test_License_GetLicensesByRecord() public {
        bytes32 recordId = _registerContent(alice);
        _createLicenseETH(recordId, alice, 1 ether);
        _createLicenseETH(recordId, alice, 2 ether);

        uint256[] memory ids = diamond.getLicensesByRecord(recordId);
        assertEq(ids.length, 2);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                    DISPUTE FACET TESTS (15 tests)
    // ═══════════════════════════════════════════════════════════════════════

    function test_Dispute_InitiateETH() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        assertTrue(disputeId != bytes32(0));
        assertTrue(diamond.hasActiveDispute(recordId));
    }

    function test_Dispute_InsufficientStake_Reverts() public {
        // Now with stakeConfig set (minStakeAmount=0.1 ether), low values should revert
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        vm.expectRevert();
        diamond.initiateDispute{value: 0.01 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );
    }

    function test_Dispute_DoubleDispute_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(charlie);
        vm.expectRevert();
        diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence2"
        );
    }

    function test_Dispute_RespondToDispute() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        AxiomTypesV2.Dispute memory d = diamond.getDispute(disputeId);
        assertEq(uint8(d.status), uint8(AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD));
    }

    function test_Dispute_SubmitEvidence() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Owner responds, moving to EVIDENCE_PERIOD
        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        // Challenger submits more evidence
        vm.prank(bob);
        diamond.submitEvidence(disputeId, "ipfs://evidence2");
    }

    function test_Dispute_ResolveByTimeout_ChallengerWins() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Warp past response period (3 days + 1 second)
        vm.warp(block.timestamp + 3 days + 1);

        diamond.resolveByTimeout(disputeId);

        AxiomTypesV2.Dispute memory d = diamond.getDispute(disputeId);
        assertEq(uint8(d.status), uint8(AxiomTypesV2.DisputeStatus.RESOLVED_VALID));
    }

    function test_Dispute_ResolveByTimeout_OwnerWins() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Owner responds
        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        // Warp past evidence period (7 days + 1 second)
        vm.warp(block.timestamp + 7 days + 1);

        diamond.resolveByTimeout(disputeId);

        AxiomTypesV2.Dispute memory d = diamond.getDispute(disputeId);
        assertEq(uint8(d.status), uint8(AxiomTypesV2.DisputeStatus.RESOLVED_INVALID));
    }

    function test_Dispute_ClaimStake_ChallengerWins() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Warp past deadline -> challenger wins
        vm.warp(block.timestamp + 3 days + 1);
        diamond.resolveByTimeout(disputeId);

        uint256 bobBalBefore = bob.balance;

        vm.prank(bob);
        uint256 claimed = diamond.claimStake(disputeId);

        assertTrue(claimed > 0);
        assertGt(bob.balance, bobBalBefore);
    }

    function test_Dispute_ClaimStake_OwnerWins() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        // Warp past evidence period -> owner wins
        vm.warp(block.timestamp + 7 days + 1);
        diamond.resolveByTimeout(disputeId);

        uint256 aliceBalBefore = alice.balance;

        vm.prank(alice);
        uint256 claimed = diamond.claimStake(disputeId);

        assertTrue(claimed > 0);
        assertGt(alice.balance, aliceBalBefore);
    }

    function test_Dispute_ClaimStake_Unauthorized_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.warp(block.timestamp + 3 days + 1);
        diamond.resolveByTimeout(disputeId);

        // Charlie can't claim
        vm.prank(charlie);
        vm.expectRevert();
        diamond.claimStake(disputeId);
    }

    function test_Dispute_GetDisputesByRecord() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        bytes32[] memory disputes = diamond.getDisputesByRecord(recordId);
        assertEq(disputes.length, 1);
    }

    function test_Dispute_NoActiveDispute() public {
        bytes32 recordId = _registerContent(alice);
        assertFalse(diamond.hasActiveDispute(recordId));
    }

    function test_Dispute_GetStakeConfig() public view {
        AxiomTypesV2.StakeConfig memory cfg = diamond.getStakeConfig();
        assertEq(cfg.minStakeAmount, 0.1 ether);
        assertEq(cfg.protocolFeeBps, 500);
    }

    function test_Dispute_ConfigurationIsAdminOnlyAndIdempotent() public {
        AxiomTypesV2.StakeConfig memory config = _stakeConfig(address(0));

        vm.prank(bob);
        vm.expectRevert("DisputeFacet: missing admin role");
        diamond.configureStakeConfig(config);

        diamond.configureStakeConfig(config);
        AxiomTypesV2.StakeConfig memory actual = diamond.getStakeConfig();
        assertEq(keccak256(abi.encode(actual)), keccak256(abi.encode(config)));

        diamond.configureStakeConfig(config);
        actual = diamond.getStakeConfig();
        assertEq(keccak256(abi.encode(actual)), keccak256(abi.encode(config)));
    }

    function test_Dispute_ArbitratorConfigurationIsAdminOnlyAndIdempotent() public {
        vm.prank(bob);
        vm.expectRevert("DisputeFacet: missing admin role");
        diamond.setArbitrator(address(mockArbitrator), false);

        diamond.setArbitrator(address(mockArbitrator), true);
        diamond.setArbitrator(address(mockArbitrator), true);
        address[] memory arbitrators = diamond.getApprovedArbitrators();
        assertEq(arbitrators.length, 1);
        assertEq(arbitrators[0], address(mockArbitrator));

        diamond.setArbitrator(address(mockArbitrator), false);
        assertFalse(diamond.isArbitratorApproved(address(mockArbitrator)));
    }

    function test_Dispute_GetDispute() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        AxiomTypesV2.Dispute memory d = diamond.getDispute(disputeId);
        assertEq(d.challenger, bob);
        assertEq(d.recordId, recordId);
        assertEq(d.stakeAmount, 0.5 ether);
    }

    function test_Dispute_ResolveBeforeDeadline_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Try to resolve immediately
        vm.expectRevert();
        diamond.resolveByTimeout(disputeId);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //              ADDITIONAL DISPUTE TESTS (Coverage Boost)
    // ═══════════════════════════════════════════════════════════════════════

    function test_Dispute_SettleDispute() public {
        uint256 ownerKey = 0xA11CE;
        uint256 challengerKey = 0xB0B;
        address owner = vm.addr(ownerKey);
        address challenger = vm.addr(challengerKey);
        vm.deal(owner, 10 ether);
        vm.deal(challenger, 10 ether);
        bytes32 recordId = _registerContent(owner);

        vm.prank(challenger);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        uint16 challengerShare = 6_000;
        bytes32 digest = diamond.settlementDigest(disputeId, challengerShare);
        (uint8 ownerV, bytes32 ownerR, bytes32 ownerS) = vm.sign(ownerKey, digest);
        (uint8 challengerV, bytes32 challengerR, bytes32 challengerS) = vm.sign(challengerKey, digest);

        diamond.settleDispute(
            disputeId,
            challengerShare,
            abi.encodePacked(ownerR, ownerS, ownerV),
            abi.encodePacked(challengerR, challengerS, challengerV)
        );

        AxiomTypesV2.Dispute memory d = diamond.getDispute(disputeId);
        assertEq(uint8(d.status), uint8(AxiomTypesV2.DisputeStatus.SETTLED));
        assertEq(d.stakeAmount, 0);
    }

    function test_Dispute_SettleAlreadyResolved_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Warp past response period for timeout resolution to work
        vm.warp(block.timestamp + 3 days + 1);
        diamond.resolveByTimeout(disputeId);

        // Try to settle a resolved dispute
        vm.expectRevert();
        diamond.settleDispute(disputeId, 6000, "", "");
    }

    function test_Dispute_GetDisputesByChallenger() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        bytes32[] memory disputes = diamond.getDisputesByChallenger(bob);
        assertEq(disputes.length, 1);
    }

    function test_Dispute_GetActiveDisputesTracksLifecycle() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        bytes32[] memory active = diamond.getActiveDisputes(0, 10);
        assertEq(active.length, 1);
        assertEq(active[0], disputeId);
        assertEq(diamond.getActiveDisputes(1, 10).length, 0);

        vm.warp(block.timestamp + 3 days + 1);
        diamond.resolveByTimeout(disputeId);
        assertEq(diamond.getActiveDisputes(0, 10).length, 0);
    }

    function test_Dispute_GetMinimumStake() public {
        bytes32 recordId = _registerContent(alice);
        uint256 minStake = diamond.getMinimumStake(recordId);
        assertEq(minStake, 0.1 ether); // Configured through the production admin API
    }

    function test_Dispute_DoubleClaim_ReturnsZero() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Warp past response period for timeout resolution
        vm.warp(block.timestamp + 3 days + 1);
        diamond.resolveByTimeout(disputeId);

        vm.prank(bob);
        diamond.claimStake(disputeId);

        // Second claim should return 0 (stake already zeroed)
        vm.prank(bob);
        uint256 secondClaim = diamond.claimStake(disputeId);
        assertEq(secondClaim, 0);
    }

    function test_Dispute_RespondNotOwner_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Charlie is not the content owner
        vm.prank(charlie);
        vm.expectRevert();
        diamond.respondToDispute(disputeId, "ipfs://response");
    }

    function test_Dispute_SubmitEvidenceWrongStatus_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Status is PENDING, not EVIDENCE_PERIOD
        vm.prank(bob);
        vm.expectRevert();
        diamond.submitEvidence(disputeId, "ipfs://evidence2");
    }

    function test_Dispute_IsArbitratorApproved() public view {
        assertFalse(diamond.isArbitratorApproved(alice));
    }

    function test_Dispute_GetApprovedArbitrators() public view {
        address[] memory arbs = diamond.getApprovedArbitrators();
        assertEq(arbs.length, 1); // mockArbitrator approved in setUp
        assertEq(arbs[0], address(mockArbitrator));
    }

    function test_Dispute_InitiateDifferentReasons() public {
        // Register multiple contents to avoid double-dispute check
        bytes32 recordId1 = _registerContent(alice);
        vm.warp(block.timestamp + 1);
        bytes32 recordId2 = _registerContent(alice);

        vm.prank(bob);
        diamond.initiateDispute{value: 0.5 ether}(
            recordId1, AxiomTypesV2.DisputeReason.FALSE_ATTRIBUTION, "ipfs://evidence1"
        );

        vm.prank(bob);
        diamond.initiateDispute{value: 0.5 ether}(
            recordId2, AxiomTypesV2.DisputeReason.HARMFUL_CONTENT, "ipfs://evidence2"
        );

        assertTrue(diamond.hasActiveDispute(recordId1));
        assertTrue(diamond.hasActiveDispute(recordId2));
    }

    // ═══════════════════════════════════════════════════════════════════════
    //              ADDITIONAL LICENSE TESTS (Coverage Boost)
    // ═══════════════════════════════════════════════════════════════════════

    function test_License_PurchaseERC20() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        uint256 licenseId = diamond.createLicense(
            recordId, AxiomTypesV2.LicenseType.COMMERCIAL_SINGLE, 10 ether, address(mockToken), 500, 0, false, false, ""
        );

        // Bob approves and purchases with ERC20
        vm.prank(bob);
        mockToken.approve(address(diamond), 10 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense(licenseId, 0);

        assertEq(diamond.ownerOf(tokenId), bob);
    }

    function test_License_SetTerritoryRestrictions() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(alice);
        diamond.setTerritoryRestrictions(licenseId, "ipfs://territories/us-only");
    }

    function test_License_SetTerritoryRestrictions_NotLicensor_Reverts() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        vm.expectRevert();
        diamond.setTerritoryRestrictions(licenseId, "ipfs://territories");
    }

    function test_License_HasValidLicense() public {
        bytes32 recordId = _registerContent(alice);
        (bool isValid, AxiomTypesV2.LicenseType lt) = diamond.hasValidLicense(bob, recordId);
        assertFalse(isValid);
        assertEq(uint8(lt), uint8(AxiomTypesV2.LicenseType.NONE));
    }

    function test_License_GetLicensesByOwnerTracksTransfers() public {
        assertEq(diamond.getLicensesByOwner(bob).length, 0);

        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 0);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense(licenseId, 0);

        uint256[] memory bobTokens = diamond.getLicensesByOwner(bob);
        assertEq(bobTokens.length, 1);
        assertEq(bobTokens[0], tokenId);

        vm.prank(bob);
        diamond.transferFrom(bob, charlie, tokenId);

        assertEq(diamond.getLicensesByOwner(bob).length, 0);
        uint256[] memory charlieTokens = diamond.getLicensesByOwner(charlie);
        assertEq(charlieTokens.length, 1);
        assertEq(charlieTokens[0], tokenId);
    }

    function test_License_TreasuryConfigurationIsAdminOnlyNonzeroAndIdempotent() public {
        assertEq(diamond.getLicenseTreasury(), treasury);

        vm.prank(bob);
        vm.expectRevert("LicenseFacet: missing admin role");
        diamond.setLicenseTreasury(charlie);

        vm.expectRevert(AxiomTypesV2.ZeroAddress.selector);
        diamond.setLicenseTreasury(address(0));

        diamond.setLicenseTreasury(charlie);
        assertEq(diamond.getLicenseTreasury(), charlie);

        diamond.setLicenseTreasury(charlie);
        assertEq(diamond.getLicenseTreasury(), charlie);
    }

    function test_License_CustomTypeRequiresTerms_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        vm.expectRevert();
        diamond.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.CUSTOM,
            1 ether,
            address(0),
            500,
            0,
            false,
            false,
            "" // empty customTermsURI
        );
    }

    function test_License_CustomTypeWithTerms() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        uint256 licenseId = diamond.createLicense(
            recordId, AxiomTypesV2.LicenseType.CUSTOM, 1 ether, address(0), 500, 0, false, false, "ipfs://custom-terms"
        );

        AxiomTypesV2.License memory lic = diamond.getLicense(licenseId);
        assertEq(uint8(lic.licenseType), uint8(AxiomTypesV2.LicenseType.CUSTOM));
    }

    function test_License_DeactivateNotLicensor_Reverts() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        vm.expectRevert();
        diamond.deactivateLicense(licenseId);
    }

    function test_License_SafeTransferFrom() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        // Bob safe-transfers to charlie (an EOA)
        vm.prank(bob);
        diamond.safeTransferFrom(bob, charlie, tokenId);

        assertEq(diamond.ownerOf(tokenId), charlie);
    }

    function test_License_PurchaseWithRoyaltySplit() public {
        bytes32 recordId = _registerContent(alice);

        // Set up royalty split first
        address[] memory recipients = new address[](2);
        recipients[0] = alice;
        recipients[1] = charlie;
        uint16[] memory shares = new uint16[](2);
        shares[0] = 7000;
        shares[1] = 3000;
        vm.prank(alice);
        diamond.setRoyaltySplit(recordId, recipients, shares);

        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        uint256 aliceBefore = alice.balance;
        uint256 charlieBefore = charlie.balance;

        vm.prank(bob);
        diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        // Verify royalties were distributed
        assertGt(alice.balance, aliceBefore);
        assertGt(charlie.balance, charlieBefore);
    }

    function test_License_PurchaseWithExpiry() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        uint256 licenseId = diamond.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.CC_BY,
            1 ether,
            address(0),
            500,
            uint40(block.timestamp + 365 days),
            false,
            false,
            ""
        );

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 30 days);

        assertTrue(diamond.isLicenseValid(tokenId));
    }

    function test_License_ExpiredLicense_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        uint256 licenseId = diamond.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.CC_BY,
            1 ether,
            address(0),
            500,
            uint40(block.timestamp + 1 hours),
            false,
            false,
            ""
        );

        // Warp past expiry
        vm.warp(block.timestamp + 2 hours);

        vm.prank(bob);
        vm.expectRevert();
        diamond.purchaseLicense{value: 1 ether}(licenseId, 0);
    }

    function test_License_ZeroPrice() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        uint256 licenseId =
            diamond.createLicense(recordId, AxiomTypesV2.LicenseType.CC0, 0, address(0), 0, 0, false, false, "");

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense(licenseId, 0);

        assertEq(diamond.ownerOf(tokenId), bob);
    }

    function test_License_ApproveToSelf_Reverts() public {
        bytes32 recordId = _registerContent(alice);
        uint256 licenseId = _createLicenseETH(recordId, alice, 1 ether);

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 0);

        vm.prank(bob);
        vm.expectRevert();
        diamond.approve(bob, tokenId); // Can't approve owner
    }

    function test_License_SetApprovalForAll_Self_Reverts() public {
        vm.prank(bob);
        vm.expectRevert();
        diamond.setApprovalForAll(bob, true);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //        DISPUTE FACET - ESCALATION & TOKEN TESTS (Coverage Boost)
    // ═══════════════════════════════════════════════════════════════════════

    function test_Dispute_InitiateWithToken() public {
        diamond.configureStakeConfig(_stakeConfig(address(mockToken)));

        bytes32 recordId = _registerContent(alice);

        // Bob approves tokens and initiates
        vm.prank(bob);
        mockToken.approve(address(diamond), 1 ether);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDisputeWithToken(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence", address(mockToken), 1 ether
        );

        assertTrue(disputeId != bytes32(0));
        assertTrue(diamond.hasActiveDispute(recordId));

        // Reset stakeConfig to ETH mode
        diamond.configureStakeConfig(_stakeConfig(address(0)));
    }

    function test_Dispute_InitiateWithToken_WrongToken_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        // stakeConfig is set to ETH (address(0)), so using any token should fail
        vm.prank(bob);
        vm.expectRevert();
        diamond.initiateDisputeWithToken(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence", address(mockToken), 1 ether
        );
    }

    function test_Dispute_EscalateToArbitration() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Owner responds -> EVIDENCE_PERIOD
        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        // Bob escalates to arbitration
        uint256 arbFee = mockArbitrator.fee();
        vm.prank(bob);
        diamond.escalateToArbitration{value: arbFee}(disputeId, address(mockArbitrator));

        AxiomTypesV2.Dispute memory d = diamond.getDispute(disputeId);
        assertEq(uint8(d.status), uint8(AxiomTypesV2.DisputeStatus.ARBITRATION));
        assertEq(d.arbitrator, address(mockArbitrator));
    }

    function test_Dispute_EscalateWrongStatus_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Status is PENDING, not EVIDENCE_PERIOD
        uint256 arbFee = mockArbitrator.fee();
        vm.prank(bob);
        vm.expectRevert();
        diamond.escalateToArbitration{value: arbFee}(disputeId, address(mockArbitrator));
    }

    function test_Dispute_EscalateUnapprovedArbitrator_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        // Use an unapproved address as arbitrator
        vm.prank(bob);
        vm.expectRevert();
        diamond.escalateToArbitration{value: 1 ether}(disputeId, address(0xDEAD));
    }

    function test_Dispute_RuleChallengerWins() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        uint256 arbFee = mockArbitrator.fee();
        vm.prank(bob);
        diamond.escalateToArbitration{value: arbFee}(disputeId, address(mockArbitrator));

        // Arbitrator rules in favor of challenger (ruling=1)
        mockArbitrator.callRule(100, 1); // externalId=100, ruling=CHALLENGER

        AxiomTypesV2.Dispute memory d = diamond.getDispute(disputeId);
        assertEq(uint8(d.status), uint8(AxiomTypesV2.DisputeStatus.RESOLVED_VALID));
    }

    function test_Dispute_RuleOwnerWins() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        uint256 arbFee = mockArbitrator.fee();
        vm.prank(bob);
        diamond.escalateToArbitration{value: arbFee}(disputeId, address(mockArbitrator));

        // Arbitrator rules in favor of owner (ruling=2)
        mockArbitrator.callRule(100, 2);

        AxiomTypesV2.Dispute memory d = diamond.getDispute(disputeId);
        assertEq(uint8(d.status), uint8(AxiomTypesV2.DisputeStatus.RESOLVED_INVALID));
    }

    function test_Dispute_AppealLifecycle() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        uint256 arbitrationFee = mockArbitrator.fee();
        vm.prank(bob);
        diamond.escalateToArbitration{value: arbitrationFee}(disputeId, address(mockArbitrator));
        mockArbitrator.callRule(100, 1);

        assertEq(diamond.getAppealDeadline(disputeId), 5 days);

        vm.prank(alice);
        bytes32 appealId = diamond.appeal{value: 0.2 ether}(disputeId, "ipfs://appeal");
        assertNotEq(appealId, bytes32(0));
        assertEq(uint8(diamond.getDispute(disputeId).status), uint8(AxiomTypesV2.DisputeStatus.APPEALED));
        assertEq(diamond.getAppealDeadline(disputeId), 0);

        mockArbitrator.callRule(100, 2);
        assertEq(uint8(diamond.getDispute(disputeId).status), uint8(AxiomTypesV2.DisputeStatus.RESOLVED_INVALID));
        assertEq(diamond.getAppealDeadline(disputeId), 0);
    }

    function test_Dispute_EscalateInsufficientFee_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        // Send less than arbitration fee
        vm.prank(bob);
        vm.expectRevert();
        diamond.escalateToArbitration{value: 0.01 ether}(disputeId, address(mockArbitrator));
    }

    function test_Dispute_RespondAfterDeadline_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Warp past response deadline
        vm.warp(block.timestamp + 4 days);

        vm.prank(alice);
        vm.expectRevert();
        diamond.respondToDispute(disputeId, "ipfs://late-response");
    }

    // DID AxiomFacets interface additions
    function test_Dispute_EscalateWithExcessFee_Refunds() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        uint256 arbFee = mockArbitrator.fee();
        uint256 excess = 1 ether;
        uint256 bobBalBefore = bob.balance;

        vm.prank(bob);
        diamond.escalateToArbitration{value: arbFee + excess}(disputeId, address(mockArbitrator));

        // Bob should get excess refunded
        assertGe(bob.balance, bobBalBefore - arbFee - 1); // within dust
    }

    function test_Dispute_SubmitEvidenceDuringArbitration() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        vm.prank(alice);
        diamond.respondToDispute(disputeId, "ipfs://response");

        uint256 arbFee = mockArbitrator.fee();
        vm.prank(bob);
        diamond.escalateToArbitration{value: arbFee}(disputeId, address(mockArbitrator));

        // Arbitration is a separate terminal evidence phase; additional
        // evidence is rejected once the case has been handed to the arbiter.
        vm.prank(bob);
        vm.expectRevert();
        diamond.submitEvidence(disputeId, "ipfs://arbitration-evidence");
    }

    // Allow test contract to receive ETH
    receive() external payable {}
}
