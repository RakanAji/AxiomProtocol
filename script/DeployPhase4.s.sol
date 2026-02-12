// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AxiomRouter} from "../src/AxiomRouter.sol";
import {AxiomRegistry} from "../src/core/AxiomRegistry.sol";
import {AxiomTreasury} from "../src/core/AxiomTreasury.sol";
import {AxiomIdentity} from "../src/core/AxiomIdentity.sol";
import {AxiomAccess} from "../src/access/AxiomAccess.sol";
import {AxiomDIDRegistry} from "../src/core/AxiomDIDRegistry.sol";
import {AxiomLicenseFacet} from "../src/core/AxiomLicenseFacet.sol";
import {AxiomDisputeFacet} from "../src/core/AxiomDisputeFacet.sol";
import {AxiomPrivacyFacet} from "../src/core/AxiomPrivacyFacet.sol";

/**
 * @title DeployPhase4
 * @notice Master deployment script — deploys the full Axiom Diamond from scratch
 * @dev Deploys AxiomRouter proxy + all 8 facets and wires them together.
 *      Split into helper functions to avoid "Stack too deep" errors.
 *
 * Usage:
 *   forge script script/DeployPhase4.s.sol:DeployPhase4 \
 *     --rpc-url $RPC_URL --broadcast --verify
 */
contract DeployPhase4 is Script {

    function run() public {
        address admin = msg.sender;
        address treasury = msg.sender;

        console2.log("=== Axiom Protocol: Phase 4 Master Deployment ===");
        console2.log("Admin:", admin);
        console2.log("Treasury:", treasury);

        vm.startBroadcast();

        // Step 1: Deploy Router Proxy
        AxiomRouter router = _deployRouter(admin, treasury);

        // Step 2-3: Deploy & wire all facets (split into helpers to stay under stack limit)
        _deployAndWireCoreFacets(router);
        _deployAndWireBusinessFacets(router);
        _deployAndWirePrivacyFacet(router);

        vm.stopBroadcast();

        console2.log("\n=== Phase 4 Deployment Complete ===");
        console2.log("Router Proxy:", address(router));
    }

    // ──────────────────────────────────────────────────────────
    //  Router Deployment
    // ──────────────────────────────────────────────────────────

    function _deployRouter(
        address _admin,
        address _treasury
    ) internal returns (AxiomRouter) {
        console2.log("\n[1/10] Deploying AxiomRouter implementation...");
        AxiomRouter routerImpl = new AxiomRouter();

        console2.log("[2/10] Deploying ERC1967 Proxy...");
        bytes memory initData = abi.encodeWithSelector(
            AxiomRouter.initialize.selector,
            _admin,
            _treasury
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(routerImpl), initData);
        AxiomRouter router = AxiomRouter(payable(address(proxy)));
        console2.log("   Router Proxy:", address(router));
        return router;
    }

    // ──────────────────────────────────────────────────────────
    //  Core Facets: Registry, Treasury, Identity, Access, DID
    // ──────────────────────────────────────────────────────────

    function _deployAndWireCoreFacets(AxiomRouter _router) internal {
        console2.log("\n[3/10] Deploying core facets...");

        _wireRegistry(_router);
        _wireTreasury(_router);
        _wireIdentity(_router);
        _wireAccess(_router);
        _wireDID(_router);
    }

    function _wireRegistry(AxiomRouter _router) internal {
        AxiomRegistry facet = new AxiomRegistry();
        console2.log("   AxiomRegistry:", address(facet));

        bytes4[] memory sel = new bytes4[](7);
        sel[0] = AxiomRegistry.register.selector;
        sel[1] = AxiomRegistry.batchRegister.selector;
        sel[2] = AxiomRegistry.revoke.selector;
        sel[3] = AxiomRegistry.verify.selector;
        sel[4] = AxiomRegistry.getRecord.selector;
        sel[5] = AxiomRegistry.getRecordsByIssuer.selector;
        sel[6] = AxiomRegistry.getTotalRecords.selector;
        _router.addFacetSelectors(address(facet), sel);
        console2.log("[4/10] Wired AxiomRegistry (7 selectors)");
    }

    function _wireTreasury(AxiomRouter _router) internal {
        AxiomTreasury facet = new AxiomTreasury();
        console2.log("   AxiomTreasury:", address(facet));

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
        _router.addFacetSelectors(address(facet), sel);
        console2.log("[5/10] Wired AxiomTreasury (10 selectors)");
    }

    function _wireIdentity(AxiomRouter _router) internal {
        AxiomIdentity facet = new AxiomIdentity();
        console2.log("   AxiomIdentity:", address(facet));

        bytes4[] memory sel = new bytes4[](7);
        sel[0] = AxiomIdentity.registerIdentity.selector;
        sel[1] = AxiomIdentity.updateIdentity.selector;
        sel[2] = AxiomIdentity.verifyIdentity.selector;
        sel[3] = AxiomIdentity.revokeVerification.selector;
        sel[4] = AxiomIdentity.resolveIdentity.selector;
        sel[5] = AxiomIdentity.resolveByName.selector;
        sel[6] = AxiomIdentity.isIdentityVerified.selector;
        _router.addFacetSelectors(address(facet), sel);
        console2.log("[6/10] Wired AxiomIdentity (7 selectors)");
    }

    function _wireAccess(AxiomRouter _router) internal {
        AxiomAccess facet = new AxiomAccess();
        console2.log("   AxiomAccess:", address(facet));

        bytes4[] memory sel = new bytes4[](6);
        sel[0] = AxiomAccess.banAddress.selector;
        sel[1] = AxiomAccess.unbanAddress.selector;
        sel[2] = AxiomAccess.isBanned.selector;
        sel[3] = AxiomAccess.disputeContent.selector;
        sel[4] = AxiomAccess.setRateLimit.selector;
        sel[5] = AxiomAccess.setMaxBatchSize.selector;
        _router.addFacetSelectors(address(facet), sel);
        console2.log("[7/10] Wired AxiomAccess (6 selectors)");
    }

    function _wireDID(AxiomRouter _router) internal {
        AxiomDIDRegistry facet = new AxiomDIDRegistry();
        console2.log("   AxiomDIDRegistry:", address(facet));

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
        _router.addFacetSelectors(address(facet), sel);
        console2.log("[8/10] Wired AxiomDIDRegistry (19 selectors)");
    }

    // ──────────────────────────────────────────────────────────
    //  Business Facets: License + Dispute
    // ──────────────────────────────────────────────────────────

    function _deployAndWireBusinessFacets(AxiomRouter _router) internal {
        console2.log("\n[9/10] Wiring License & Dispute facets...");
        _wireLicense(_router);
        _wireDispute(_router);
    }

    function _wireLicense(AxiomRouter _router) internal {
        AxiomLicenseFacet facet = new AxiomLicenseFacet();
        console2.log("   AxiomLicenseFacet:", address(facet));

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
        _router.addFacetSelectors(address(facet), sel);
        console2.log("   Wired AxiomLicenseFacet (24 selectors)");
    }

    function _wireDispute(AxiomRouter _router) internal {
        AxiomDisputeFacet facet = new AxiomDisputeFacet();
        console2.log("   AxiomDisputeFacet:", address(facet));

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
        _router.addFacetSelectors(address(facet), sel);
        console2.log("   Wired AxiomDisputeFacet (13 selectors)");
    }

    // ──────────────────────────────────────────────────────────
    //  Privacy Facet
    // ──────────────────────────────────────────────────────────

    function _deployAndWirePrivacyFacet(AxiomRouter _router) internal {
        console2.log("\n[10/10] Wiring AxiomPrivacyFacet...");
        AxiomPrivacyFacet facet = new AxiomPrivacyFacet();
        console2.log("   AxiomPrivacyFacet:", address(facet));

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
        _router.addFacetSelectors(address(facet), sel);
        console2.log("   Wired AxiomPrivacyFacet (10 selectors)");
    }
}
