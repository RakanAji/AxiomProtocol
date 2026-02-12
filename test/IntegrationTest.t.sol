// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Core
import {AxiomRouter} from "../src/AxiomRouter.sol";
import {AxiomStorage} from "../src/storage/AxiomStorage.sol";
import {AxiomTypes} from "../src/libraries/AxiomTypes.sol";
import {AxiomTypesV2} from "../src/libraries/AxiomTypesV2.sol";

// Facets
import {AxiomRegistry} from "../src/core/AxiomRegistry.sol";
import {AxiomTreasury} from "../src/core/AxiomTreasury.sol";
import {AxiomIdentity} from "../src/core/AxiomIdentity.sol";
import {AxiomAccess} from "../src/access/AxiomAccess.sol";
import {AxiomDIDRegistry} from "../src/core/AxiomDIDRegistry.sol";
import {AxiomLicenseFacet} from "../src/core/AxiomLicenseFacet.sol";
import {AxiomDisputeFacet} from "../src/core/AxiomDisputeFacet.sol";
import {AxiomPrivacyFacet} from "../src/core/AxiomPrivacyFacet.sol";

// Interface
import {AxiomFacets} from "../src/interfaces/AxiomFacets.sol";

/**
 * @title IntegrationTest
 * @notice End-to-end integration test proving the Diamond pattern works across all facets
 * @dev Tests the full user flow:
 *      1. DID registration (DIDRegistry facet)
 *      2. Content registration (Registry facet)
 *      3. License creation (License facet)
 *      4. License purchase (License facet)
 *      5. NFT balance verification (License facet)
 *      6. Private content registration (Privacy facet)
 *      7. Ownership verification via ZK proof (Privacy facet)
 */
contract IntegrationTest is Test {
    // ============ State ============
    AxiomRouter public router;
    AxiomFacets public diamond; // Unified interface for all facets

    // Facet implementations
    AxiomRegistry public registryFacet;
    AxiomTreasury public treasuryFacet;
    AxiomIdentity public identityFacet;
    AxiomAccess public accessFacet;
    AxiomDIDRegistry public didFacet;
    AxiomLicenseFacet public licenseFacet;
    AxiomDisputeFacet public disputeFacet;
    AxiomPrivacyFacet public privacyFacet;

    // Test actors
    address public admin = address(0xAD);
    address public treasury = address(0xFEE);
    address public creator = address(0xC1);
    address public buyer = address(0xB1);
    address public operator = address(0x0B);

    // Constants
    uint256 public constant BASE_FEE = 0.0001 ether;

    // ============ Setup ============

    function setUp() public {
        // Deploy implementation + proxy
        AxiomRouter routerImpl = new AxiomRouter();
        bytes memory initData = abi.encodeWithSelector(
            AxiomRouter.initialize.selector,
            admin,
            treasury
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(routerImpl), initData);
        router = AxiomRouter(payable(address(proxy)));
        diamond = AxiomFacets(payable(address(proxy)));

        // Deploy all facets
        registryFacet = new AxiomRegistry();
        treasuryFacet = new AxiomTreasury();
        identityFacet = new AxiomIdentity();
        accessFacet = new AxiomAccess();
        didFacet = new AxiomDIDRegistry();
        licenseFacet = new AxiomLicenseFacet();
        disputeFacet = new AxiomDisputeFacet();
        privacyFacet = new AxiomPrivacyFacet();

        // Wire all facets (Diamond Cut)
        vm.startPrank(admin);
        _wireRegistryFacet();
        _wireTreasuryFacet();
        _wireIdentityFacet();
        _wireAccessFacet();
        _wireDIDFacet();
        _wireLicenseFacet();
        _wireDisputeFacet();
        _wirePrivacyFacet();

        // Grant operator role
        bytes32 operatorRole = router.OPERATOR_ROLE();
        router.grantRole(operatorRole, operator);
        vm.stopPrank();

        // Fund test actors
        vm.deal(creator, 100 ether);
        vm.deal(buyer, 100 ether);
    }

    // ============ Integration Tests ============

    /**
     * @notice Full end-to-end flow across all facets via the Diamond proxy
     */
    function test_FullIntegrationFlow() public {
        // ── Step 1: Creator registers DID ──
        console2.log("Step 1: Registering DID...");
        vm.startPrank(creator);
        
        diamond.registerDID(
            "did:ethr:31337:0xC1",
            keccak256("did-doc-hash"),
            "publicKeyJwk"
        );
        
        assertTrue(diamond.hasDID(creator), "Creator should have a DID");
        assertTrue(diamond.isDIDActive(creator), "DID should be active");
        assertEq(diamond.getDIDString(creator), "did:ethr:31337:0xC1");
        vm.stopPrank();
        console2.log("   DID registered successfully");

        // ── Step 2: Creator registers content ──
        console2.log("Step 2: Registering content...");
        bytes32 contentHash = keccak256("my-original-photograph");
        
        vm.prank(creator);
        bytes32 recordId = diamond.register{value: BASE_FEE}(
            contentHash,
            "ipfs://QmContentMetadata"
        );
        
        assertTrue(recordId != bytes32(0), "Record ID should be non-zero");
        AxiomTypes.AxiomRecord memory record = diamond.getRecord(recordId);
        assertEq(record.issuer, creator, "Issuer should be creator");
        assertEq(record.contentHash, contentHash, "Content hash should match");
        assertEq(uint8(record.status), uint8(AxiomTypes.ContentStatus.ACTIVE));
        console2.log("   Content registered, recordId:", vm.toString(recordId));

        // ── Step 3: Creator creates a license for the content ──
        console2.log("Step 3: Creating license...");
        vm.prank(creator);
        uint256 licenseId = diamond.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.CC_BY,
            0.01 ether,             // price
            address(0),             // ETH payment
            500,                    // 5% royalty
            uint40(block.timestamp + 365 days),
            false,                  // non-exclusive
            false,                  // non-sublicensable
            "ipfs://QmLicenseTerms"
        );
        
        assertTrue(licenseId > 0, "License ID should be positive");
        console2.log("   License created, licenseId:", licenseId);

        // ── Step 4: Buyer purchases the license ──
        console2.log("Step 4: Buyer purchasing license...");
        vm.prank(buyer);
        uint256 tokenId = diamond.purchaseLicense{value: 0.01 ether}(
            licenseId,
            uint40(365 days)
        );
        
        assertTrue(tokenId > 0, "Token ID should be positive");
        console2.log("   License purchased, tokenId:", tokenId);

        // ── Step 5: Verify buyer's NFT balance ──
        console2.log("Step 5: Verifying NFT balance...");
        assertEq(diamond.balanceOf(buyer), 1, "Buyer should own 1 NFT");
        assertEq(diamond.ownerOf(tokenId), buyer, "Buyer should own the token");
        console2.log("   NFT balance verified: 1 NFT owned by buyer");

        // ── Step 6: Creator privately registers content ──
        console2.log("Step 6: Privately registering content...");
        bytes32 privateContentHash = keccak256("my-secret-content");
        bytes32 commitment = keccak256(abi.encodePacked(creator, "secret", "nullifier"));
        bytes32 nullifierHash = keccak256(abi.encodePacked("nullifier", privateContentHash));
        bytes memory validProof = bytes("valid"); // Mock ZK proof

        vm.prank(creator);
        bytes32 privateRecordId = diamond.privateRegister{value: 0}(
            privateContentHash,
            commitment,
            nullifierHash,
            validProof,
            "ipfs://QmPrivateMetadata"
        );
        
        assertTrue(privateRecordId != bytes32(0), "Private record ID should be non-zero");
        assertTrue(diamond.nullifierUsed(nullifierHash), "Nullifier should be used");
        assertTrue(diamond.contentExists(privateContentHash), "Content should exist");
        console2.log("   Private content registered");

        // ── Step 7: Verify ownership via ZK proof ──
        console2.log("Step 7: Verifying private ownership...");
        bool isOwner = diamond.verifyOwnership(
            privateRecordId,
            commitment,
            validProof
        );
        assertTrue(isOwner, "Ownership verification should pass");
        console2.log("   Ownership verified via ZK proof");

        // ── Step 8: Verify private record data ──
        console2.log("Step 8: Checking private record data...");
        AxiomTypesV2.PrivateRecord memory privRecord = diamond.getPrivateRecord(privateRecordId);
        assertEq(privRecord.contentHash, privateContentHash, "Content hash should match");
        assertEq(privRecord.commitment, commitment, "Commitment should match");
        assertEq(privRecord.nullifierHash, nullifierHash, "Nullifier hash should match");
        assertEq(uint8(privRecord.status), uint8(AxiomTypesV2.ContentStatus.ACTIVE));
        assertFalse(privRecord.metadataDeleted, "Metadata should not be deleted");
        console2.log("   Private record data validated");

        console2.log("\n=== Full Integration Test PASSED ===");
    }

    /**
     * @notice Test that nullifier prevents double-registration in privacy facet
     */
    function test_PrivacyNullifierPreventsDoubleRegistration() public {
        bytes32 contentHash = keccak256("unique-content");
        bytes32 commitment = keccak256("commitment1");
        bytes32 nullifierHash = keccak256("nullifier1");
        bytes memory validProof = bytes("valid");

        vm.prank(creator);
        diamond.privateRegister(contentHash, commitment, nullifierHash, validProof, "");

        // Second registration with same nullifier should fail
        vm.prank(creator);
        vm.expectRevert(
            abi.encodeWithSelector(AxiomTypesV2.NullifierAlreadyUsed.selector, nullifierHash)
        );
        diamond.privateRegister(
            keccak256("different-content"),
            keccak256("commitment2"),
            nullifierHash, // Same nullifier!
            validProof,
            ""
        );
    }

    /**
     * @notice Test that invalid ZK proof is rejected
     */
    function test_PrivacyInvalidProofRejected() public {
        bytes32 contentHash = keccak256("content");
        bytes32 commitment = keccak256("commitment");
        bytes32 nullifierHash = keccak256("nullifier");
        bytes memory invalidProof = bytes("invalid-garbage-proof");

        vm.prank(creator);
        vm.expectRevert(AxiomTypesV2.InvalidZKProof.selector);
        diamond.privateRegister(contentHash, commitment, nullifierHash, invalidProof, "");
    }

    /**
     * @notice Test ownership verification with wrong commitment
     */
    function test_PrivacyWrongCommitmentFails() public {
        bytes32 contentHash = keccak256("content");
        bytes32 commitment = keccak256("real-commitment");
        bytes32 nullifierHash = keccak256("nullifier");
        bytes memory validProof = bytes("valid");

        vm.prank(creator);
        bytes32 recordId = diamond.privateRegister(
            contentHash, commitment, nullifierHash, validProof, ""
        );

        // Wrong commitment should return false
        bool isOwner = diamond.verifyOwnership(
            recordId,
            keccak256("wrong-commitment"),
            validProof
        );
        assertFalse(isOwner, "Wrong commitment should fail verification");
    }

    /**
     * @notice Test that DID registration cross-facet with content registration
     */
    function test_DIDAndContentCrossFacet() public {
        // Register DID
        vm.startPrank(creator);
        diamond.registerDID("did:ethr:31337:creator", keccak256("doc"), "jwk");
        
        // Register content through the same proxy
        bytes32 recordId = diamond.register{value: BASE_FEE}(
            keccak256("cross-facet-content"),
            "ipfs://cross"
        );
        vm.stopPrank();

        // Both should be queryable via the same proxy
        assertTrue(diamond.hasDID(creator));
        assertTrue(recordId != bytes32(0));
        assertEq(diamond.getRecord(recordId).issuer, creator);
    }

    /**
     * @notice Test privacy records are tracked by commitment
     */
    function test_PrivacyRecordsByCommitment() public {
        bytes32 commitment = keccak256("shared-commitment");
        bytes memory validProof = bytes("valid");

        // Register multiple private records with same commitment
        vm.startPrank(creator);
        bytes32 record1 = diamond.privateRegister(
            keccak256("content1"), commitment, keccak256("null1"), validProof, ""
        );
        bytes32 record2 = diamond.privateRegister(
            keccak256("content2"), commitment, keccak256("null2"), validProof, ""
        );
        vm.stopPrank();

        bytes32[] memory records = diamond.getRecordsByCommitment(commitment);
        assertEq(records.length, 2, "Should have 2 records for this commitment");
        assertEq(records[0], record1);
        assertEq(records[1], record2);
    }

    // ============ Selector Wiring Helpers ============

    function _wireRegistryFacet() internal {
        bytes4[] memory sel = new bytes4[](7);
        sel[0] = AxiomRegistry.register.selector;
        sel[1] = AxiomRegistry.batchRegister.selector;
        sel[2] = AxiomRegistry.revoke.selector;
        sel[3] = AxiomRegistry.verify.selector;
        sel[4] = AxiomRegistry.getRecord.selector;
        sel[5] = AxiomRegistry.getRecordsByIssuer.selector;
        sel[6] = AxiomRegistry.getTotalRecords.selector;
        router.addFacetSelectors(address(registryFacet), sel);
    }

    function _wireTreasuryFacet() internal {
        bytes4[] memory sel = new bytes4[](10);
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
        router.addFacetSelectors(address(treasuryFacet), sel);
    }

    function _wireIdentityFacet() internal {
        bytes4[] memory sel = new bytes4[](7);
        sel[0] = AxiomIdentity.registerIdentity.selector;
        sel[1] = AxiomIdentity.updateIdentity.selector;
        sel[2] = AxiomIdentity.verifyIdentity.selector;
        sel[3] = AxiomIdentity.revokeVerification.selector;
        sel[4] = AxiomIdentity.resolveIdentity.selector;
        sel[5] = AxiomIdentity.resolveByName.selector;
        sel[6] = AxiomIdentity.isIdentityVerified.selector;
        router.addFacetSelectors(address(identityFacet), sel);
    }

    function _wireAccessFacet() internal {
        bytes4[] memory sel = new bytes4[](6);
        sel[0] = AxiomAccess.banAddress.selector;
        sel[1] = AxiomAccess.unbanAddress.selector;
        sel[2] = AxiomAccess.isBanned.selector;
        sel[3] = AxiomAccess.disputeContent.selector;
        sel[4] = AxiomAccess.setRateLimit.selector;
        sel[5] = AxiomAccess.setMaxBatchSize.selector;
        router.addFacetSelectors(address(accessFacet), sel);
    }

    function _wireDIDFacet() internal {
        bytes4[] memory sel = new bytes4[](19);
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
    }

    function _wireLicenseFacet() internal {
        bytes4[] memory sel = new bytes4[](24);
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
        router.addFacetSelectors(address(licenseFacet), sel);
    }

    function _wireDisputeFacet() internal {
        bytes4[] memory sel = new bytes4[](13);
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
        router.addFacetSelectors(address(disputeFacet), sel);
    }

    function _wirePrivacyFacet() internal {
        bytes4[] memory sel = new bytes4[](10);
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
        router.addFacetSelectors(address(privacyFacet), sel);
    }
}
