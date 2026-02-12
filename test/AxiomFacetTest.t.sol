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
import {AxiomStorage} from "../src/storage/AxiomStorage.sol";
import {AxiomFacets} from "../src/interfaces/AxiomFacets.sol";
import {AxiomTypesV2} from "../src/libraries/AxiomTypesV2.sol";

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
    function appealCost(uint256, bytes calldata) external pure returns (uint256) { return 0; }
    function appealPeriod(uint256) external pure returns (uint256, uint256) { return (0, 0); }

    // Called by the proxy to rule on a dispute
    function callRule(uint256 _externalId, uint256 _ruling) external {
        // Call rule on the axiom proxy as the arbitrator
        (bool ok,) = axiomProxy.call(
            abi.encodeWithSignature("rule(uint256,uint256)", _externalId, _ruling)
        );
        require(ok, "rule failed");
    }
}

// ─── Test Config Facet to set proxy storage via delegatecall ───────────
contract TestConfigFacet {
    function setStakeConfigForTest(
        uint256 _minStake,
        uint256 _minAppealStake,
        address _stakeToken,
        uint16 _protocolFeeBps,
        uint16 _rewardBps,
        uint16 _slashBps,
        uint40 _responsePeriod,
        uint40 _evidencePeriod,
        uint40 _appealPeriod
    ) external {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.stakeConfig = AxiomTypesV2.StakeConfig({
            minStakeAmount: _minStake,
            minAppealStake: _minAppealStake,
            stakeToken: _stakeToken,
            protocolFeeBps: _protocolFeeBps,
            rewardBps: _rewardBps,
            slashBps: _slashBps,
            responsePeriod: _responsePeriod,
            evidencePeriod: _evidencePeriod,
            appealPeriod: _appealPeriod
        });
    }

    function approveArbitratorForTest(address _arbitrator) external {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.approvedArbitrators[_arbitrator] = true;
        s.arbitratorList.push(_arbitrator);
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

        // Wire Registry (7)
        bytes4[] memory sel = new bytes4[](7);
        sel[0] = AxiomRegistry.register.selector;
        sel[1] = AxiomRegistry.batchRegister.selector;
        sel[2] = AxiomRegistry.revoke.selector;
        sel[3] = AxiomRegistry.verify.selector;
        sel[4] = AxiomRegistry.getRecord.selector;
        sel[5] = AxiomRegistry.getRecordsByIssuer.selector;
        sel[6] = AxiomRegistry.getTotalRecords.selector;
        router.addFacetSelectors(address(regFacet), sel);

        // Wire Treasury (10)
        sel = new bytes4[](10);
        sel[0] = AxiomTreasury.setBaseFee.selector;
        sel[1] = AxiomTreasury.setEnterpriseRate.selector;
        sel[2] = AxiomTreasury.grantEnterpriseStatus.selector;
        sel[3] = AxiomTreasury.revokeEnterpriseStatus.selector;
        sel[4] = AxiomTreasury.withdraw.selector;
        sel[5] = AxiomTreasury.setTreasuryWallet.selector;
        sel[6] = AxiomTreasury.getFee.selector;
        sel[7] = AxiomTreasury.getBaseFee.selector;
        sel[8] = AxiomTreasury.getTotalFeesCollected.selector;
        sel[9] = AxiomTreasury.isEnterpriseUser.selector;
        router.addFacetSelectors(address(treFacet), sel);

        // Wire Identity (7)
        sel = new bytes4[](7);
        sel[0] = AxiomIdentity.registerIdentity.selector;
        sel[1] = AxiomIdentity.updateIdentity.selector;
        sel[2] = AxiomIdentity.verifyIdentity.selector;
        sel[3] = AxiomIdentity.revokeVerification.selector;
        sel[4] = AxiomIdentity.resolveIdentity.selector;
        sel[5] = AxiomIdentity.resolveByName.selector;
        sel[6] = AxiomIdentity.isIdentityVerified.selector;
        router.addFacetSelectors(address(idFacet), sel);

        // Wire Access (6)
        sel = new bytes4[](6);
        sel[0] = AxiomAccess.banAddress.selector;
        sel[1] = AxiomAccess.unbanAddress.selector;
        sel[2] = AxiomAccess.isBanned.selector;
        sel[3] = AxiomAccess.disputeContent.selector;
        sel[4] = AxiomAccess.setRateLimit.selector;
        sel[5] = AxiomAccess.setMaxBatchSize.selector;
        router.addFacetSelectors(address(acFacet), sel);

        // Wire DID (19)
        sel = new bytes4[](19);
        sel[0] = AxiomDIDRegistry.registerDID.selector;
        sel[1] = AxiomDIDRegistry.updateDIDDocument.selector;
        sel[2] = AxiomDIDRegistry.setServiceEndpoint.selector;
        sel[3] = AxiomDIDRegistry.revokeDID.selector;
        sel[4] = AxiomDIDRegistry.addDelegate.selector;
        sel[5] = AxiomDIDRegistry.revokeDelegate.selector;
        sel[6] = AxiomDIDRegistry.validDelegate.selector;
        sel[7] = AxiomDIDRegistry.getDelegates.selector;
        sel[8] = AxiomDIDRegistry.setVerificationLevel.selector;
        sel[9] = AxiomDIDRegistry.getVerificationLevel.selector;
        sel[10] = AxiomDIDRegistry.meetsVerificationLevel.selector;
        sel[11] = AxiomDIDRegistry.resolveDID.selector;
        sel[12] = AxiomDIDRegistry.getIdentity.selector;
        sel[13] = AxiomDIDRegistry.hasDID.selector;
        sel[14] = AxiomDIDRegistry.isDIDActive.selector;
        sel[15] = AxiomDIDRegistry.getDIDString.selector;
        sel[16] = AxiomDIDRegistry.setAttribute.selector;
        sel[17] = AxiomDIDRegistry.revokeAttribute.selector;
        sel[18] = AxiomDIDRegistry.verifySignature.selector;
        router.addFacetSelectors(address(didFacet), sel);

        // Wire License (32)
        sel = new bytes4[](32);
        sel[0] = AxiomLicenseFacet.createLicense.selector;
        sel[1] = AxiomLicenseFacet.updateLicense.selector;
        sel[2] = AxiomLicenseFacet.deactivateLicense.selector;
        sel[3] = AxiomLicenseFacet.purchaseLicense.selector;
        sel[4] = AxiomLicenseFacet.purchaseLicenseFor.selector;
        sel[5] = AxiomLicenseFacet.balanceOf.selector;
        sel[6] = AxiomLicenseFacet.ownerOf.selector;
        sel[7] = bytes4(keccak256("transferFrom(address,address,uint256)"));
        sel[8] = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
        sel[9] = bytes4(keccak256("safeTransferFrom(address,address,uint256,bytes)"));
        sel[10] = AxiomLicenseFacet.approve.selector;
        sel[11] = AxiomLicenseFacet.setApprovalForAll.selector;
        sel[12] = AxiomLicenseFacet.getApproved.selector;
        sel[13] = AxiomLicenseFacet.isApprovedForAll.selector;
        sel[14] = AxiomLicenseFacet.name.selector;
        sel[15] = AxiomLicenseFacet.symbol.selector;
        sel[16] = AxiomLicenseFacet.tokenURI.selector;
        sel[17] = AxiomLicenseFacet.royaltyInfo.selector;
        sel[18] = AxiomLicenseFacet.setRoyaltySplit.selector;
        sel[19] = AxiomLicenseFacet.getLicense.selector;
        sel[20] = AxiomLicenseFacet.getLicensesByRecord.selector;
        sel[21] = AxiomLicenseFacet.isLicenseValid.selector;
        sel[22] = AxiomLicenseFacet.getRoyaltySplit.selector;
        sel[23] = AxiomLicenseFacet.supportsInterface.selector;
        sel[24] = AxiomLicenseFacet.hasValidLicense.selector;
        sel[25] = AxiomLicenseFacet.claimRoyalties.selector;
        sel[26] = AxiomLicenseFacet.claimRoyaltiesToken.selector;
        sel[27] = AxiomLicenseFacet.pendingRoyalties.selector;
        sel[28] = AxiomLicenseFacet.createSublicense.selector;
        sel[29] = AxiomLicenseFacet.purchaseSublicense.selector;
        sel[30] = AxiomLicenseFacet.setTerritoryRestrictions.selector;
        sel[31] = AxiomLicenseFacet.getLicensesByOwner.selector;
        router.addFacetSelectors(address(licFacet), sel);

        // Wire Dispute (20)
        sel = new bytes4[](20);
        sel[0] = AxiomDisputeFacet.initiateDispute.selector;
        sel[1] = AxiomDisputeFacet.initiateDisputeWithToken.selector;
        sel[2] = AxiomDisputeFacet.respondToDispute.selector;
        sel[3] = AxiomDisputeFacet.submitEvidence.selector;
        sel[4] = AxiomDisputeFacet.escalateToArbitration.selector;
        sel[5] = AxiomDisputeFacet.resolveByTimeout.selector;
        sel[6] = AxiomDisputeFacet.claimStake.selector;
        sel[7] = AxiomDisputeFacet.getDispute.selector;
        sel[8] = AxiomDisputeFacet.getDisputesByRecord.selector;
        sel[9] = AxiomDisputeFacet.hasActiveDispute.selector;
        sel[10] = AxiomDisputeFacet.getStakeConfig.selector;
        sel[11] = AxiomDisputeFacet.getApprovedArbitrators.selector;
        sel[12] = AxiomDisputeFacet.isArbitratorApproved.selector;
        sel[13] = AxiomDisputeFacet.settleDispute.selector;
        sel[14] = AxiomDisputeFacet.getDisputesByChallenger.selector;
        sel[15] = AxiomDisputeFacet.getActiveDisputes.selector;
        sel[16] = AxiomDisputeFacet.getMinimumStake.selector;
        sel[17] = AxiomDisputeFacet.appeal.selector;
        sel[18] = AxiomDisputeFacet.getAppealDeadline.selector;
        sel[19] = AxiomDisputeFacet.rule.selector;
        router.addFacetSelectors(address(disFacet), sel);

        // Wire Privacy (10)
        sel = new bytes4[](10);
        sel[0] = AxiomPrivacyFacet.privateRegister.selector;
        sel[1] = AxiomPrivacyFacet.verifyOwnership.selector;
        sel[2] = AxiomPrivacyFacet.requestErasure.selector;
        sel[3] = AxiomPrivacyFacet.confirmErasure.selector;
        sel[4] = AxiomPrivacyFacet.getPrivateRecord.selector;
        sel[5] = AxiomPrivacyFacet.contentExists.selector;
        sel[6] = AxiomPrivacyFacet.nullifierUsed.selector;
        sel[7] = AxiomPrivacyFacet.isMetadataDeleted.selector;
        sel[8] = AxiomPrivacyFacet.getGDPRRequest.selector;
        sel[9] = AxiomPrivacyFacet.getRecordsByCommitment.selector;
        router.addFacetSelectors(address(priFacet), sel);

        // Wire TestConfigFacet (2) - for setting stake config and approving arbitrators through proxy
        TestConfigFacet cfgFacet = new TestConfigFacet();
        sel = new bytes4[](2);
        sel[0] = TestConfigFacet.setStakeConfigForTest.selector;
        sel[1] = TestConfigFacet.approveArbitratorForTest.selector;
        router.addFacetSelectors(address(cfgFacet), sel);

        // Grant VERIFIER_ROLE to verifier
        router.grantRole(VERIFIER_ROLE, verifier);

        // Fund test accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(charlie, 100 ether);

        // Configure stake config through proxy
        (bool ok,) = address(diamond).call(
            abi.encodeWithSelector(
                TestConfigFacet.setStakeConfigForTest.selector,
                0.1 ether,  // minStakeAmount
                0.2 ether,  // minAppealStake
                address(0),  // stakeToken (ETH)
                500,         // protocolFeeBps (5%)
                8000,        // rewardBps (80%)
                5000,        // slashBps (50%)
                uint40(3 days),    // responsePeriod
                uint40(7 days),    // evidencePeriod
                uint40(5 days)     // appealPeriod
            )
        );
        require(ok, "setStakeConfig failed");

        // Approve mock arbitrator through proxy
        mockArbitrator.setProxy(address(diamond));
        (ok,) = address(diamond).call(
            abi.encodeWithSelector(
                TestConfigFacet.approveArbitratorForTest.selector,
                address(mockArbitrator)
            )
        );
        require(ok, "approveArbitrator failed");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //                        HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    function _registerContent(address user) internal returns (bytes32) {
        bytes32 hash = keccak256(abi.encodePacked("content", user, block.timestamp));
        vm.prank(user);
        return diamond.register{value: 0.01 ether}(hash, "ipfs://metadata");
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
            500,        // 5% royalty
            0,          // no expiry
            false,      // non-exclusive
            false,      // non-sublicensable
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
            recordId, AxiomTypesV2.LicenseType.CC_BY, 1 ether,
            address(0), 500, 0, false, false, ""
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
            recordId, AxiomTypesV2.LicenseType.CC_BY, 1 ether,
            address(0), 10001, 0, false, false, "" // >10000 bps
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
            recordId, AxiomTypesV2.LicenseType.CC_BY, 1 ether,
            address(0), 500, 0, true, false, "" // exclusive
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
        (bool ok, bytes memory data) = address(diamond).call(
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

        (bool ok, bytes memory data) = address(diamond).call(
            abi.encodeWithSignature("isLicenseValid(uint256)", tokenId)
        );
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
        bytes32 recordId = _registerContent(alice);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDispute{value: 0.5 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );

        // Settle with 60/40 split
        diamond.settleDispute(disputeId, 6000, "", "");

        AxiomTypesV2.Dispute memory d = diamond.getDispute(disputeId);
        assertEq(uint8(d.status), uint8(AxiomTypesV2.DisputeStatus.SETTLED));
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

    function test_Dispute_GetActiveDisputes() public view {
        bytes32[] memory disputes = diamond.getActiveDisputes(0, 10);
        assertEq(disputes.length, 0); // Stub returns empty
    }

    function test_Dispute_GetMinimumStake() public {
        bytes32 recordId = _registerContent(alice);
        uint256 minStake = diamond.getMinimumStake(recordId);
        assertEq(minStake, 0.1 ether); // Configured via TestConfigFacet
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
            recordId, AxiomTypesV2.LicenseType.COMMERCIAL_SINGLE, 10 ether,
            address(mockToken), 500, 0, false, false, ""
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

    function test_License_ClaimRoyalties_ReturnsZero() public {
        bytes32 recordId = _registerContent(alice);
        uint256 claimed = diamond.claimRoyalties(recordId);
        assertEq(claimed, 0);
    }

    function test_License_ClaimRoyaltiesToken_ReturnsZero() public {
        bytes32 recordId = _registerContent(alice);
        uint256 claimed = diamond.claimRoyaltiesToken(recordId, address(mockToken));
        assertEq(claimed, 0);
    }

    function test_License_PendingRoyalties_ReturnsZero() public {
        bytes32 recordId = _registerContent(alice);
        uint256 pending = diamond.pendingRoyalties(alice, recordId);
        assertEq(pending, 0);
    }

    function test_License_CreateSublicense_Reverts() public {
        vm.expectRevert();
        diamond.createSublicense(1, 1 ether, 30 days);
    }

    function test_License_PurchaseSublicense_Reverts() public {
        vm.expectRevert();
        diamond.purchaseSublicense{value: 1 ether}(1);
    }

    function test_License_GetLicensesByOwner_Reverts() public {
        vm.expectRevert();
        diamond.getLicensesByOwner(alice);
    }

    function test_License_CustomTypeRequiresTerms_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        vm.expectRevert();
        diamond.createLicense(
            recordId, AxiomTypesV2.LicenseType.CUSTOM, 1 ether,
            address(0), 500, 0, false, false, "" // empty customTermsURI
        );
    }

    function test_License_CustomTypeWithTerms() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        uint256 licenseId = diamond.createLicense(
            recordId, AxiomTypesV2.LicenseType.CUSTOM, 1 ether,
            address(0), 500, 0, false, false, "ipfs://custom-terms"
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
            recordId, AxiomTypesV2.LicenseType.CC_BY, 1 ether,
            address(0), 500, uint40(block.timestamp + 365 days), false, false, ""
        );

        vm.prank(bob);
        uint256 tokenId = diamond.purchaseLicense{value: 1 ether}(licenseId, 30 days);

        assertTrue(diamond.isLicenseValid(tokenId));
    }

    function test_License_ExpiredLicense_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        vm.prank(alice);
        uint256 licenseId = diamond.createLicense(
            recordId, AxiomTypesV2.LicenseType.CC_BY, 1 ether,
            address(0), 500, uint40(block.timestamp + 1 hours), false, false, ""
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
        uint256 licenseId = diamond.createLicense(
            recordId, AxiomTypesV2.LicenseType.CC0, 0,
            address(0), 0, 0, false, false, ""
        );

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
        // First configure stakeToken to mockToken through TestConfigFacet
        (bool ok,) = address(diamond).call(
            abi.encodeWithSelector(
                TestConfigFacet.setStakeConfigForTest.selector,
                0.1 ether,
                0.2 ether,
                address(mockToken), // ERC20 mode
                500, 8000, 5000,
                uint40(3 days), uint40(7 days), uint40(5 days)
            )
        );
        require(ok);

        bytes32 recordId = _registerContent(alice);

        // Bob approves tokens and initiates
        vm.prank(bob);
        mockToken.approve(address(diamond), 1 ether);

        vm.prank(bob);
        bytes32 disputeId = diamond.initiateDisputeWithToken(
            recordId,
            AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT,
            "ipfs://evidence",
            address(mockToken),
            1 ether
        );

        assertTrue(disputeId != bytes32(0));
        assertTrue(diamond.hasActiveDispute(recordId));

        // Reset stakeConfig to ETH mode
        (ok,) = address(diamond).call(
            abi.encodeWithSelector(
                TestConfigFacet.setStakeConfigForTest.selector,
                0.1 ether, 0.2 ether, address(0),
                500, 8000, 5000,
                uint40(3 days), uint40(7 days), uint40(5 days)
            )
        );
        require(ok);
    }

    function test_Dispute_InitiateWithToken_WrongToken_Reverts() public {
        bytes32 recordId = _registerContent(alice);

        // stakeConfig is set to ETH (address(0)), so using any token should fail
        vm.prank(bob);
        vm.expectRevert();
        diamond.initiateDisputeWithToken(
            recordId,
            AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT,
            "ipfs://evidence",
            address(mockToken),
            1 ether
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

    function test_Dispute_AppealStub_Reverts() public {
        vm.expectRevert();
        diamond.appeal{value: 0.1 ether}(bytes32(uint256(1)), "reason");
    }

    function test_Dispute_GetAppealDeadline() public view {
        uint256 deadline = diamond.getAppealDeadline(bytes32(uint256(1)));
        assertEq(deadline, 0); // Stub returns 0
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

        // Evidence can be submitted during arbitration
        vm.prank(bob);
        diamond.submitEvidence(disputeId, "ipfs://arbitration-evidence");
    }

    // Allow test contract to receive ETH
    receive() external payable {}
}
