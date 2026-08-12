// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {AxiomRouter} from "../../src/AxiomRouter.sol";
import {AxiomRegistry} from "../../src/core/AxiomRegistry.sol";
import {AxiomTreasury} from "../../src/core/AxiomTreasury.sol";
import {AxiomIdentity} from "../../src/core/AxiomIdentity.sol";
import {AxiomAccess} from "../../src/access/AxiomAccess.sol";
import {AxiomDIDRegistry} from "../../src/core/AxiomDIDRegistry.sol";
import {AxiomLicenseFacet} from "../../src/core/AxiomLicenseFacet.sol";
import {AxiomDisputeFacet} from "../../src/core/AxiomDisputeFacet.sol";
import {AxiomPrivacyFacet} from "../../src/core/AxiomPrivacyFacet.sol";
import {AxiomDisputeSetupFacet} from "../../src/core/AxiomDisputeSetupFacet.sol";
import {AxiomTypes} from "../../src/libraries/AxiomTypes.sol";
import {AxiomTypesV2} from "../../src/libraries/AxiomTypesV2.sol";
import {AxiomFacets} from "../../src/interfaces/AxiomFacets.sol";
import {IZKVerifier} from "../../src/interfaces/IZKVerifier.sol";

contract SecurityVerifier is IZKVerifier {
    uint256 public constant NUM_PUBLIC_INPUTS = 3;
    bool public constant PRODUCTION_READY = true;
    bytes32 public expectedSignalsHash;

    function expect(uint256[] calldata signals) external {
        expectedSignalsHash = keccak256(abi.encode(signals));
    }

    function clearExpectation() external {
        expectedSignalsHash = bytes32(0);
    }

    function verifyProof(uint256[2] calldata, uint256[2][2] calldata, uint256[2] calldata, uint256[] calldata signals)
        external
        view
        returns (bool)
    {
        if (signals.length != 3) return false;
        uint256 field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        bool fieldSafe = signals[0] < field && signals[1] < field && signals[2] < field;
        return fieldSafe && (expectedSignalsHash == bytes32(0) || expectedSignalsHash == keccak256(abi.encode(signals)));
    }
}

contract FeeOnTransferToken is IERC20 {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - 1;
        totalSupply -= 1;
        return true;
    }
}

contract SecurityArbitrator {
    uint256 public constant COST = 0.01 ether;
    uint256 public constant APPEAL_COST = 0.02 ether;
    uint256 public nextId = 1;
    address public router;

    function setRouter(address _router) external {
        router = _router;
    }

    function arbitrationCost(bytes calldata) external pure returns (uint256) {
        return COST;
    }

    function createDispute(uint256, bytes calldata) external payable returns (uint256 id) {
        require(msg.value == COST);
        id = nextId++;
    }

    function appealCost(uint256, bytes calldata) external pure returns (uint256) {
        return APPEAL_COST;
    }

    function appeal(uint256, bytes calldata) external payable {
        require(msg.value == APPEAL_COST);
    }

    function rule(uint256 id, uint256 ruling) external {
        (bool ok,) = router.call(abi.encodeWithSignature("rule(uint256,uint256)", id, ruling));
        require(ok, "rule failed");
    }

    function ruleFromArbitrator(uint256 id, uint256 ruling) external {
        (bool ok, bytes memory result) = router.call(abi.encodeWithSignature("rule(uint256,uint256)", id, ruling));
        if (!ok) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}

contract AxiomCoreHardeningTest is Test {
    AxiomRouter internal router;
    AxiomFacets internal axiom;
    AxiomDisputeFacet internal disputeFacet;
    SecurityVerifier internal verifier;
    SecurityArbitrator internal arbitrator;

    uint256 internal constant OWNER_PK = 0xA11CE;
    uint256 internal constant CHALLENGER_PK = 0xB0B;
    address internal owner;
    address internal challenger;
    address internal attacker = address(0xBAD);
    address internal treasury = address(0xBEEF);

    function setUp() public {
        owner = vm.addr(OWNER_PK);
        challenger = vm.addr(CHALLENGER_PK);
        vm.deal(owner, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(attacker, 100 ether);

        AxiomRouter implementation = new AxiomRouter();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation), abi.encodeCall(AxiomRouter.initialize, (address(this), treasury))
        );
        router = AxiomRouter(payable(address(proxy)));
        axiom = AxiomFacets(address(router));

        AxiomRegistry registry = new AxiomRegistry();
        AxiomTreasury treasuryFacet = new AxiomTreasury();
        AxiomIdentity identity = new AxiomIdentity();
        AxiomAccess access = new AxiomAccess();
        AxiomDIDRegistry did = new AxiomDIDRegistry();
        AxiomLicenseFacet license = new AxiomLicenseFacet();
        disputeFacet = new AxiomDisputeFacet();
        AxiomPrivacyFacet privacy = new AxiomPrivacyFacet();

        _route(address(registry), _registrySelectors());
        _route(address(treasuryFacet), _treasurySelectors());
        _route(address(identity), _identitySelectors());
        _route(address(access), _accessSelectors());
        _route(address(did), _didSelectors());
        _route(address(license), _licenseSelectors());
        _route(address(disputeFacet), _disputeSelectors());
        _route(address(privacy), _privacySelectors());

        axiom.setLicenseTreasury(treasury);
        verifier = new SecurityVerifier();
        axiom.setZKVerifier(address(verifier));

        arbitrator = new SecurityArbitrator();
        arbitrator.setRouter(address(router));
        axiom.setArbitrator(address(arbitrator), true);
        axiom.configureStakeConfig(_stakeConfig());
    }

    function testNativeRoleAuthorizationAndRouterGuards() public {
        vm.startPrank(attacker);
        vm.expectRevert("AxiomTreasury: missing admin role");
        axiom.setBaseFee(0);
        vm.expectRevert("AxiomIdentity: missing operator role");
        axiom.verifyIdentity(owner);
        vm.expectRevert("LicenseFacet: missing admin role");
        axiom.setLicenseTreasury(attacker);
        vm.expectRevert("DisputeFacet: missing admin role");
        axiom.configureStakeConfig(_stakeConfig());
        vm.stopPrank();

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(uint32(1));
        vm.expectRevert(AxiomRouter.InvalidFacetAddress.selector);
        router.addFacetSelectors(attacker, selectors);

        selectors[0] = bytes4(0);
        vm.expectRevert(abi.encodeWithSelector(AxiomRouter.FacetNotFound.selector, bytes4(0)));
        router.addFacetSelectors(address(disputeFacet), selectors);
    }

    function testRegistryPaginationAndAcceptedFeeAccounting() public {
        bytes32 first = _register(owner, keccak256("one"));

        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = keccak256("one");
        hashes[1] = keccak256("two");
        hashes[2] = keccak256("two");
        string[] memory uris = new string[](3);
        vm.prank(owner);
        bytes32[] memory ids = axiom.batchRegister{value: 0.0003 ether}(hashes, uris);

        assertEq(ids[0], bytes32(0));
        assertTrue(ids[1] != bytes32(0));
        assertEq(ids[2], bytes32(0));
        assertEq(axiom.getTotalFeesCollected(), 0.0002 ether);
        bytes32[] memory page = axiom.getRecordIds(0, 10);
        assertEq(page.length, 2);
        assertEq(page[0], first);
        assertEq(page[1], ids[1]);
    }

    function testLicenseAuthorizationTermsAndDeactivationPreservePurchase() public {
        bytes32 recordId = _register(owner, keccak256("licensed"));
        vm.prank(attacker);
        vm.expectRevert();
        axiom.createLicense(
            recordId, AxiomTypesV2.LicenseType.COMMERCIAL_SINGLE, 1 ether, address(0), 0, 0, false, false, ""
        );

        vm.prank(owner);
        uint256 licenseId = axiom.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.COMMERCIAL_SINGLE,
            1 ether,
            address(0),
            0,
            uint40(block.timestamp + 30 days),
            false,
            false,
            ""
        );
        vm.prank(challenger);
        uint256 tokenId = axiom.purchaseLicense{value: 1 ether}(licenseId, 7 days);

        vm.prank(owner);
        vm.expectRevert();
        axiom.updateLicense(licenseId, 2 ether, 0, false);
        vm.prank(owner);
        axiom.deactivateLicense(licenseId);

        assertTrue(axiom.isLicenseValid(tokenId));
        (bool valid, AxiomTypesV2.LicenseType licenseType) = axiom.hasValidLicense(challenger, recordId);
        assertTrue(valid);
        assertEq(uint8(licenseType), uint8(AxiomTypesV2.LicenseType.COMMERCIAL_SINGLE));
        assertTrue(bytes(axiom.tokenURI(tokenId)).length > 29);
    }

    function testExclusiveLicenseTracksTransferee() public {
        bytes32 recordId = _register(owner, keccak256("exclusive"));
        vm.prank(owner);
        uint256 licenseId =
            axiom.createLicense(recordId, AxiomTypesV2.LicenseType.EXCLUSIVE, 0, address(0), 0, 0, true, false, "");
        vm.prank(challenger);
        uint256 tokenId = axiom.purchaseLicense(licenseId, 0);
        vm.prank(challenger);
        axiom.transferFrom(challenger, attacker, tokenId);
        assertEq(axiom.getLicense(licenseId).licensee, attacker);
        assertTrue(bytes(axiom.tokenURI(tokenId)).length > 29);
    }

    function testFeeOnTransferLicensePaymentRevertsAtomically() public {
        FeeOnTransferToken token = new FeeOnTransferToken();
        token.mint(challenger, 10 ether);
        bytes32 recordId = _register(owner, keccak256("fee-token"));
        vm.prank(owner);
        uint256 licenseId = axiom.createLicense(
            recordId, AxiomTypesV2.LicenseType.COMMERCIAL_SINGLE, 1 ether, address(token), 0, 0, false, false, ""
        );
        vm.prank(challenger);
        token.approve(address(router), 1 ether);
        vm.prank(challenger);
        vm.expectRevert();
        axiom.purchaseLicense(licenseId, 0);
        assertEq(axiom.balanceOf(challenger), 0);
    }

    function testDisputeRejectsUnknownSelfAndNonPartyActions() public {
        vm.prank(challenger);
        vm.expectRevert();
        axiom.initiateDispute{value: 1 ether}(keccak256("unknown"), AxiomTypesV2.DisputeReason.OTHER, "ipfs://evidence");

        bytes32 recordId = _register(owner, keccak256("disputed"));
        vm.prank(owner);
        vm.expectRevert();
        axiom.initiateDispute{value: 1 ether}(recordId, AxiomTypesV2.DisputeReason.OTHER, "ipfs://evidence");

        bytes32 disputeId = _initiate(recordId);
        vm.prank(owner);
        axiom.respondToDispute(disputeId, "ipfs://response");
        uint256 arbitrationCost = arbitrator.COST();
        vm.prank(attacker);
        vm.expectRevert();
        axiom.submitEvidence(disputeId, "ipfs://not-party");
        vm.prank(attacker);
        (bool ok,) = address(axiom).call{value: arbitrationCost}(
            abi.encodeCall(AxiomDisputeFacet.escalateToArbitration, (disputeId, address(arbitrator)))
        );
        assertFalse(ok);

        bytes32[] memory active = axiom.getActiveDisputes(0, 10);
        assertEq(active.length, 1);
        assertEq(active[0], disputeId);
    }

    function testSignedSettlementValidatesShareAndPaysBothParties() public {
        bytes32 disputeId = _initiate(_register(owner, keccak256("settle")));
        vm.expectRevert();
        axiom.settleDispute(disputeId, 10_001, "", "");
        vm.expectRevert();
        axiom.settleDispute(disputeId, 2_500, "", "");

        bytes32 digest = axiom.settlementDigest(disputeId, 2_500);
        bytes memory ownerSig = _sign(OWNER_PK, digest);
        bytes memory challengerSig = _sign(CHALLENGER_PK, digest);
        uint256 ownerBefore = owner.balance;
        uint256 challengerBefore = challenger.balance;
        axiom.settleDispute(disputeId, 2_500, ownerSig, challengerSig);

        assertEq(owner.balance - ownerBefore, 0.75 ether);
        assertEq(challenger.balance - challengerBefore, 0.25 ether);
        assertFalse(axiom.hasActiveDispute(axiom.getDispute(disputeId).recordId));
    }

    function testAssignedArbitratorCanRuleAfterGovernanceRevocation() public {
        bytes32 disputeId = _initiate(_register(owner, keccak256("rule")));
        vm.prank(owner);
        axiom.respondToDispute(disputeId, "ipfs://response");
        uint256 arbitrationCost = arbitrator.COST();
        vm.prank(challenger);
        axiom.escalateToArbitration{value: arbitrationCost}(disputeId, address(arbitrator));
        axiom.setArbitrator(address(arbitrator), false);

        arbitrator.ruleFromArbitrator(1, 2);
        assertEq(uint8(axiom.getDispute(disputeId).status), uint8(AxiomTypesV2.DisputeStatus.RESOLVED_INVALID));
    }

    function testRefusedRulingReturnsCaseToEvidence() public {
        bytes32 disputeId = _initiate(_register(owner, keccak256("refusal")));
        vm.prank(owner);
        axiom.respondToDispute(disputeId, "ipfs://response");
        uint256 arbitrationCost = arbitrator.COST();
        vm.prank(challenger);
        axiom.escalateToArbitration{value: arbitrationCost}(disputeId, address(arbitrator));

        arbitrator.ruleFromArbitrator(1, 0);
        AxiomTypesV2.Dispute memory dispute = axiom.getDispute(disputeId);
        assertEq(uint8(dispute.status), uint8(AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD));
        assertEq(dispute.arbitrator, address(0));
        assertEq(dispute.externalDisputeId, bytes32(0));
    }

    function testFirstRulingKeepsRecordDisputedUntilClaimFinality() public {
        bytes32 recordId = _register(owner, keccak256("appeal-finality"));
        bytes32 disputeId = _initiate(recordId);
        vm.prank(owner);
        axiom.respondToDispute(disputeId, "ipfs://response");
        uint256 arbitrationCost = arbitrator.COST();
        vm.prank(challenger);
        axiom.escalateToArbitration{value: arbitrationCost}(disputeId, address(arbitrator));
        arbitrator.ruleFromArbitrator(1, 2);

        assertEq(uint8(axiom.getRecord(recordId).status), uint8(AxiomTypes.ContentStatus.DISPUTED));
        vm.prank(owner);
        vm.expectRevert();
        axiom.createLicense(recordId, AxiomTypesV2.LicenseType.CC0, 0, address(0), 0, 0, false, false, "");
        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(owner);
        axiom.claimStake(disputeId);
        assertEq(uint8(axiom.getRecord(recordId).status), uint8(AxiomTypes.ContentStatus.ACTIVE));
    }

    function testIssuerCannotRevokeRecordDuringDispute() public {
        bytes32 recordId = _register(owner, keccak256("revoke-race"));
        _initiate(recordId);
        vm.prank(owner);
        vm.expectRevert("AxiomRegistry: disputed record");
        axiom.revoke(recordId, "issuer revoke");
        assertEq(uint8(axiom.getRecord(recordId).status), uint8(AxiomTypes.ContentStatus.DISPUTED));
    }

    function testTreasuryCannotWithdrawEscrowedNativeStake() public {
        _initiate(_register(owner, keccak256("escrow")));
        vm.expectRevert("Insufficient unreserved balance");
        axiom.withdraw(treasury, address(router).balance);
    }

    function testPauseDoesNotConsumeExistingDisputeResponseWindow() public {
        bytes32 disputeId = _initiate(_register(owner, keccak256("pause-window")));
        router.pause();
        vm.prank(owner);
        axiom.respondToDispute(disputeId, "ipfs://response");
        vm.prank(challenger);
        axiom.submitEvidence(disputeId, "ipfs://more-evidence");
    }

    function testArbitratorReapprovalIsDeduplicated() public {
        axiom.setArbitrator(address(arbitrator), false);
        axiom.setArbitrator(address(arbitrator), true);
        address[] memory approved = axiom.getApprovedArbitrators();
        assertEq(approved.length, 1);
        assertEq(approved[0], address(arbitrator));
    }

    function testBannedUserCannotCreateAcrossModules() public {
        axiom.banAddress(attacker, "abuse");
        bytes memory proof = _proof();
        vm.startPrank(attacker);
        vm.expectRevert();
        axiom.registerDID("did:ethr:attacker", keccak256("doc"), "{jwk}");
        vm.expectRevert();
        axiom.privateRegister(keccak256("banned"), keccak256("c"), keccak256("n"), proof, "");
        vm.stopPrank();
    }

    function testERC165RequiresCompleteInstalledSelectorSet() public {
        assertTrue(router.supportsInterface(0x80ac58cd));
        bytes4[] memory selector = new bytes4[](1);
        selector[0] = AxiomLicenseFacet.balanceOf.selector;
        router.removeFacetSelectors(selector);
        assertFalse(router.supportsInterface(0x80ac58cd));
    }

    function testPrivacyRejectsETHZeroNullifierDuplicatesAndUsesThreeFieldSignals() public {
        bytes memory proof = _proof();
        vm.expectRevert("PrivacyFacet: ETH not accepted");
        axiom.privateRegister{value: 1}(
            keccak256("private"), keccak256("commitment"), keccak256("nullifier"), proof, ""
        );
        vm.expectRevert("PrivacyFacet: Zero nullifier");
        axiom.privateRegister(keccak256("private"), keccak256("commitment"), bytes32(0), proof, "");

        bytes32 recordId =
            axiom.privateRegister(keccak256("private"), keccak256("commitment"), keccak256("nullifier"), proof, "");
        assertTrue(axiom.verifyOwnership(recordId, keccak256("commitment"), proof));
        vm.expectRevert("PrivacyFacet: Content already registered");
        axiom.privateRegister(keccak256("private"), keccak256("other"), keccak256("other-nullifier"), proof, "");
    }

    function testPrivacyProofPurposeAndCallerProduceDifferentSignals() public {
        bytes memory proof = _proof();
        bytes32 contentHash = keccak256("purpose-content");
        bytes32 commitment = keccak256("purpose-commitment");
        bytes32 nullifier = keccak256("purpose-nullifier");
        bytes32 recordId = axiom.privateRegister(contentHash, commitment, nullifier, proof, "ipfs://private");

        uint256[] memory impossible = new uint256[](3);
        impossible[0] = 1;
        impossible[1] = 2;
        impossible[2] = 3;
        verifier.expect(impossible);
        assertFalse(axiom.verifyOwnership(recordId, commitment, proof));
        vm.expectRevert();
        axiom.requestErasure(recordId, proof);
        verifier.clearExpectation();
    }

    function testSetupFacetDirectAndRoutedCallsCannotBePublicReset() public {
        AxiomDisputeSetupFacet setupFacet = new AxiomDisputeSetupFacet();
        vm.prank(attacker);
        vm.expectRevert();
        setupFacet.initializeDisputeSystem();

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = AxiomDisputeSetupFacet.initializeDisputeSystem.selector;
        _route(address(setupFacet), selectors);
        vm.prank(attacker);
        vm.expectRevert("DisputeSetupFacet: missing admin role");
        (bool ok,) = address(router).call(abi.encodeCall(AxiomDisputeSetupFacet.initializeDisputeSystem, ()));
        ok;
    }

    function _stakeConfig() internal pure returns (AxiomTypesV2.StakeConfig memory config) {
        config = AxiomTypesV2.StakeConfig({
            minStakeAmount: 1 ether,
            minAppealStake: 0.2 ether,
            stakeToken: address(0),
            protocolFeeBps: 500,
            rewardBps: 0,
            slashBps: 0,
            responsePeriod: 3 days,
            evidencePeriod: 3 days,
            appealPeriod: 3 days
        });
    }

    function _register(address issuer, bytes32 contentHash) internal returns (bytes32 recordId) {
        vm.prank(issuer);
        recordId = axiom.register{value: 0.0001 ether}(contentHash, "ipfs://record");
    }

    function _initiate(bytes32 recordId) internal returns (bytes32 disputeId) {
        vm.prank(challenger);
        disputeId = axiom.initiateDispute{value: 1 ether}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        );
    }

    function _sign(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _proof() internal pure returns (bytes memory) {
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        return abi.encode(a, b, c);
    }

    function _route(address facet, bytes4[] memory selectors) internal {
        router.addFacetSelectors(facet, selectors);
    }

    function _registrySelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](8);
        s[0] = AxiomRegistry.register.selector;
        s[1] = AxiomRegistry.batchRegister.selector;
        s[2] = AxiomRegistry.revoke.selector;
        s[3] = AxiomRegistry.verify.selector;
        s[4] = AxiomRegistry.getRecord.selector;
        s[5] = AxiomRegistry.getRecordsByIssuer.selector;
        s[6] = AxiomRegistry.getTotalRecords.selector;
        s[7] = AxiomRegistry.getRecordIds.selector;
    }

    function _treasurySelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](4);
        s[0] = AxiomTreasury.setBaseFee.selector;
        s[1] = AxiomTreasury.getTotalFeesCollected.selector;
        s[2] = AxiomTreasury.setTreasuryWallet.selector;
        s[3] = AxiomTreasury.withdraw.selector;
    }

    function _identitySelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](4);
        s[0] = AxiomIdentity.registerIdentity.selector;
        s[1] = AxiomIdentity.updateIdentity.selector;
        s[2] = AxiomIdentity.verifyIdentity.selector;
        s[3] = AxiomIdentity.isIdentityVerified.selector;
    }

    function _accessSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](1);
        s[0] = AxiomAccess.banAddress.selector;
    }

    function _didSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](1);
        s[0] = AxiomDIDRegistry.registerDID.selector;
    }

    function _licenseSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](19);
        s[0] = AxiomLicenseFacet.setLicenseTreasury.selector;
        s[1] = AxiomLicenseFacet.createLicense.selector;
        s[2] = AxiomLicenseFacet.updateLicense.selector;
        s[3] = AxiomLicenseFacet.deactivateLicense.selector;
        s[4] = AxiomLicenseFacet.purchaseLicense.selector;
        s[5] = AxiomLicenseFacet.isLicenseValid.selector;
        s[6] = AxiomLicenseFacet.hasValidLicense.selector;
        s[7] = AxiomLicenseFacet.tokenURI.selector;
        s[8] = AxiomLicenseFacet.ownerOf.selector;
        s[9] = AxiomLicenseFacet.balanceOf.selector;
        s[10] = AxiomLicenseFacet.getLicense.selector;
        s[11] = AxiomLicenseFacet.getLicensesByOwner.selector;
        s[12] = AxiomLicenseFacet.transferFrom.selector;
        s[13] = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
        s[14] = bytes4(keccak256("safeTransferFrom(address,address,uint256,bytes)"));
        s[15] = AxiomLicenseFacet.approve.selector;
        s[16] = AxiomLicenseFacet.setApprovalForAll.selector;
        s[17] = AxiomLicenseFacet.getApproved.selector;
        s[18] = AxiomLicenseFacet.isApprovedForAll.selector;
    }

    function _disputeSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](17);
        s[0] = AxiomDisputeFacet.configureStakeConfig.selector;
        s[1] = AxiomDisputeFacet.setArbitrator.selector;
        s[2] = AxiomDisputeFacet.initiateDispute.selector;
        s[3] = AxiomDisputeFacet.respondToDispute.selector;
        s[4] = AxiomDisputeFacet.submitEvidence.selector;
        s[5] = AxiomDisputeFacet.escalateToArbitration.selector;
        s[6] = AxiomDisputeFacet.rule.selector;
        s[7] = AxiomDisputeFacet.settleDispute.selector;
        s[8] = AxiomDisputeFacet.settlementDigest.selector;
        s[9] = AxiomDisputeFacet.getActiveDisputes.selector;
        s[10] = AxiomDisputeFacet.hasActiveDispute.selector;
        s[11] = AxiomDisputeFacet.getDispute.selector;
        s[12] = AxiomDisputeFacet.getStakeConfig.selector;
        s[13] = AxiomDisputeFacet.claimStake.selector;
        s[14] = AxiomDisputeFacet.appeal.selector;
        s[15] = AxiomDisputeFacet.getAppealDeadline.selector;
        s[16] = AxiomDisputeFacet.getApprovedArbitrators.selector;
    }

    function _privacySelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](6);
        s[0] = AxiomPrivacyFacet.setZKVerifier.selector;
        s[1] = AxiomPrivacyFacet.privateRegister.selector;
        s[2] = AxiomPrivacyFacet.verifyOwnership.selector;
        s[3] = AxiomPrivacyFacet.approveZKVerifierForProduction.selector;
        s[4] = AxiomPrivacyFacet.isZKVerifierProductionApproved.selector;
        s[5] = AxiomPrivacyFacet.requestErasure.selector;
    }
}
