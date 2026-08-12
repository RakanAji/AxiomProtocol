// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomAccess} from "../src/access/AxiomAccess.sol";
import {AxiomDIDRegistry} from "../src/core/AxiomDIDRegistry.sol";
import {AxiomDisputeFacet} from "../src/core/AxiomDisputeFacet.sol";
import {AxiomIdentity} from "../src/core/AxiomIdentity.sol";
import {AxiomLicenseFacet} from "../src/core/AxiomLicenseFacet.sol";
import {AxiomPrivacyFacet} from "../src/core/AxiomPrivacyFacet.sol";
import {AxiomRegistry} from "../src/core/AxiomRegistry.sol";
import {AxiomTreasury} from "../src/core/AxiomTreasury.sol";

/// @notice Canonical selector inventory installed by deployment scripts and test fixtures.
/// @dev Keep native AxiomRouter selectors out of this manifest. In particular,
///      `supportsInterface(bytes4)`, `pause()`, and `unpause()` are implemented by
///      the router itself and must not be shadow-routed to a facet.
library AxiomSelectorManifest {
    function registrySelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](8);
        selectors[0] = AxiomRegistry.register.selector;
        selectors[1] = AxiomRegistry.batchRegister.selector;
        selectors[2] = AxiomRegistry.revoke.selector;
        selectors[3] = AxiomRegistry.verify.selector;
        selectors[4] = AxiomRegistry.getRecord.selector;
        selectors[5] = AxiomRegistry.getRecordsByIssuer.selector;
        selectors[6] = AxiomRegistry.getTotalRecords.selector;
        selectors[7] = AxiomRegistry.getRecordIds.selector;
    }

    function treasurySelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](10);
        selectors[0] = AxiomTreasury.setBaseFee.selector;
        selectors[1] = AxiomTreasury.setEnterpriseRate.selector;
        selectors[2] = AxiomTreasury.grantEnterpriseStatus.selector;
        selectors[3] = AxiomTreasury.revokeEnterpriseStatus.selector;
        selectors[4] = AxiomTreasury.withdraw.selector;
        selectors[5] = AxiomTreasury.setTreasuryWallet.selector;
        selectors[6] = AxiomTreasury.getFee.selector;
        selectors[7] = AxiomTreasury.getBaseFee.selector;
        selectors[8] = AxiomTreasury.getTotalFeesCollected.selector;
        selectors[9] = AxiomTreasury.isEnterpriseUser.selector;
    }

    function identitySelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](7);
        selectors[0] = AxiomIdentity.registerIdentity.selector;
        selectors[1] = AxiomIdentity.updateIdentity.selector;
        selectors[2] = AxiomIdentity.verifyIdentity.selector;
        selectors[3] = AxiomIdentity.revokeVerification.selector;
        selectors[4] = AxiomIdentity.resolveIdentity.selector;
        selectors[5] = AxiomIdentity.resolveByName.selector;
        selectors[6] = AxiomIdentity.isIdentityVerified.selector;
    }

    function accessSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](8);
        selectors[0] = AxiomAccess.banAddress.selector;
        selectors[1] = AxiomAccess.unbanAddress.selector;
        selectors[2] = AxiomAccess.isBanned.selector;
        selectors[3] = AxiomAccess.setRateLimit.selector;
        selectors[4] = AxiomAccess.setMaxBatchSize.selector;
        selectors[5] = AxiomAccess.isPaused.selector;
        selectors[6] = AxiomAccess.getRateLimitSettings.selector;
        selectors[7] = AxiomAccess.getMaxBatchSize.selector;
    }

    function didSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](22);
        selectors[0] = AxiomDIDRegistry.registerDID.selector;
        selectors[1] = AxiomDIDRegistry.updateDIDDocument.selector;
        selectors[2] = AxiomDIDRegistry.setServiceEndpoint.selector;
        selectors[3] = AxiomDIDRegistry.revokeDID.selector;
        selectors[4] = AxiomDIDRegistry.addDelegate.selector;
        selectors[5] = AxiomDIDRegistry.revokeDelegate.selector;
        selectors[6] = AxiomDIDRegistry.validDelegate.selector;
        selectors[7] = AxiomDIDRegistry.getDelegates.selector;
        selectors[8] = AxiomDIDRegistry.setVerificationLevel.selector;
        selectors[9] = AxiomDIDRegistry.getVerificationLevel.selector;
        selectors[10] = AxiomDIDRegistry.meetsVerificationLevel.selector;
        selectors[11] = AxiomDIDRegistry.resolveDID.selector;
        selectors[12] = AxiomDIDRegistry.getIdentity.selector;
        selectors[13] = AxiomDIDRegistry.hasDID.selector;
        selectors[14] = AxiomDIDRegistry.isDIDActive.selector;
        selectors[15] = AxiomDIDRegistry.getDIDString.selector;
        selectors[16] = AxiomDIDRegistry.setAttribute.selector;
        selectors[17] = AxiomDIDRegistry.revokeAttribute.selector;
        selectors[18] = AxiomDIDRegistry.verifySignature.selector;
        selectors[19] = AxiomDIDRegistry.getTotalDIDs.selector;
        selectors[20] = AxiomDIDRegistry.getAttribute.selector;
        selectors[21] = AxiomDIDRegistry.changed.selector;
    }

    function licenseSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](28);
        selectors[0] = AxiomLicenseFacet.setLicenseTreasury.selector;
        selectors[1] = AxiomLicenseFacet.getLicenseTreasury.selector;
        selectors[2] = AxiomLicenseFacet.createLicense.selector;
        selectors[3] = AxiomLicenseFacet.updateLicense.selector;
        selectors[4] = AxiomLicenseFacet.deactivateLicense.selector;
        selectors[5] = AxiomLicenseFacet.purchaseLicense.selector;
        selectors[6] = AxiomLicenseFacet.purchaseLicenseFor.selector;
        selectors[7] = AxiomLicenseFacet.balanceOf.selector;
        selectors[8] = AxiomLicenseFacet.ownerOf.selector;
        selectors[9] = bytes4(keccak256("transferFrom(address,address,uint256)"));
        selectors[10] = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
        selectors[11] = bytes4(keccak256("safeTransferFrom(address,address,uint256,bytes)"));
        selectors[12] = AxiomLicenseFacet.approve.selector;
        selectors[13] = AxiomLicenseFacet.setApprovalForAll.selector;
        selectors[14] = AxiomLicenseFacet.getApproved.selector;
        selectors[15] = AxiomLicenseFacet.isApprovedForAll.selector;
        selectors[16] = AxiomLicenseFacet.name.selector;
        selectors[17] = AxiomLicenseFacet.symbol.selector;
        selectors[18] = AxiomLicenseFacet.tokenURI.selector;
        selectors[19] = AxiomLicenseFacet.royaltyInfo.selector;
        selectors[20] = AxiomLicenseFacet.setRoyaltySplit.selector;
        selectors[21] = AxiomLicenseFacet.getLicense.selector;
        selectors[22] = AxiomLicenseFacet.getLicensesByRecord.selector;
        selectors[23] = AxiomLicenseFacet.getLicensesByOwner.selector;
        selectors[24] = AxiomLicenseFacet.hasValidLicense.selector;
        selectors[25] = AxiomLicenseFacet.isLicenseValid.selector;
        selectors[26] = AxiomLicenseFacet.getRoyaltySplit.selector;
        selectors[27] = AxiomLicenseFacet.setTerritoryRestrictions.selector;
    }

    function disputeSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](24);
        selectors[0] = AxiomDisputeFacet.configureStakeConfig.selector;
        selectors[1] = AxiomDisputeFacet.setArbitrator.selector;
        selectors[2] = AxiomDisputeFacet.initiateDispute.selector;
        selectors[3] = AxiomDisputeFacet.initiateDisputeWithToken.selector;
        selectors[4] = AxiomDisputeFacet.respondToDispute.selector;
        selectors[5] = AxiomDisputeFacet.submitEvidence.selector;
        selectors[6] = AxiomDisputeFacet.escalateToArbitration.selector;
        selectors[7] = AxiomDisputeFacet.rule.selector;
        selectors[8] = AxiomDisputeFacet.resolveByTimeout.selector;
        selectors[9] = AxiomDisputeFacet.settleDispute.selector;
        selectors[10] = AxiomDisputeFacet.settlementDigest.selector;
        selectors[11] = AxiomDisputeFacet.claimStake.selector;
        selectors[12] = AxiomDisputeFacet.getApprovedArbitrators.selector;
        selectors[13] = AxiomDisputeFacet.isArbitratorApproved.selector;
        selectors[14] = AxiomDisputeFacet.getArbitratorFee.selector;
        selectors[15] = AxiomDisputeFacet.appeal.selector;
        selectors[16] = AxiomDisputeFacet.getAppealDeadline.selector;
        selectors[17] = AxiomDisputeFacet.getDispute.selector;
        selectors[18] = AxiomDisputeFacet.getDisputesByRecord.selector;
        selectors[19] = AxiomDisputeFacet.getDisputesByChallenger.selector;
        selectors[20] = AxiomDisputeFacet.getActiveDisputes.selector;
        selectors[21] = AxiomDisputeFacet.hasActiveDispute.selector;
        selectors[22] = AxiomDisputeFacet.getStakeConfig.selector;
        selectors[23] = AxiomDisputeFacet.getMinimumStake.selector;
    }

    function privacySelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](14);
        selectors[0] = AxiomPrivacyFacet.privateRegister.selector;
        selectors[1] = AxiomPrivacyFacet.verifyOwnership.selector;
        selectors[2] = AxiomPrivacyFacet.requestErasure.selector;
        selectors[3] = AxiomPrivacyFacet.confirmErasure.selector;
        selectors[4] = AxiomPrivacyFacet.getPrivateRecord.selector;
        selectors[5] = AxiomPrivacyFacet.contentExists.selector;
        selectors[6] = AxiomPrivacyFacet.nullifierUsed.selector;
        selectors[7] = AxiomPrivacyFacet.isMetadataDeleted.selector;
        selectors[8] = AxiomPrivacyFacet.getGDPRRequest.selector;
        selectors[9] = AxiomPrivacyFacet.getRecordsByCommitment.selector;
        selectors[10] = AxiomPrivacyFacet.setZKVerifier.selector;
        selectors[11] = AxiomPrivacyFacet.getZKVerifier.selector;
        selectors[12] = AxiomPrivacyFacet.approveZKVerifierForProduction.selector;
        selectors[13] = AxiomPrivacyFacet.isZKVerifierProductionApproved.selector;
    }

    function totalFacetSelectors() internal pure returns (uint256) {
        return 121;
    }
}
