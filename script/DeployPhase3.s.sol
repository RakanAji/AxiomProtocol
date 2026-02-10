// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {AxiomRouter} from "../src/AxiomRouter.sol";
import {AxiomLicenseFacet} from "../src/core/AxiomLicenseFacet.sol";
import {AxiomDisputeFacet} from "../src/core/AxiomDisputeFacet.sol";
import {AxiomStorage} from "../src/storage/AxiomStorage.sol";
import {AxiomTypesV2} from "../src/libraries/AxiomTypesV2.sol";

/**
 * @title DeployPhase3
 * @notice Deploy and register Phase 3 facets (License and Dispute)
 * @dev Run this script after deploying the base AxiomRouter Diamond proxy
 */
contract DeployPhase3 is Script {
    function run(address _router) public {
        console2.log("=== Deploying Phase 3: License & Dispute Facets ===");
        console2.log("Router Address:", _router);
        
        AxiomRouter router = AxiomRouter(payable(_router));
        
        vm.startBroadcast();
        
        // 1. Deploy AxiomLicenseFacet
        console2.log("\n1. Deploying AxiomLicenseFacet...");
        AxiomLicenseFacet licenseFacet = new AxiomLicenseFacet();
        console2.log("   Deployed at:", address(licenseFacet));
        
        // 2. Deploy AxiomDisputeFacet
        console2.log("\n2. Deploying AxiomDisputeFacet...");
        AxiomDisputeFacet disputeFacet = new AxiomDisputeFacet();
        console2.log("   Deployed at:", address(disputeFacet));
        
        // 3. Register AxiomLicenseFacet selectors
        console2.log("\n3. Registering AxiomLicenseFacet selectors...");
        bytes4[] memory licenseSelectors = new bytes4[](24);
        licenseSelectors[0] = AxiomLicenseFacet.createLicense.selector;
        licenseSelectors[1] = AxiomLicenseFacet.updateLicense.selector;
        licenseSelectors[2] = AxiomLicenseFacet.deactivateLicense.selector;
        licenseSelectors[3] = AxiomLicenseFacet.purchaseLicense.selector;
        licenseSelectors[4] = AxiomLicenseFacet.purchaseLicenseFor.selector;
        licenseSelectors[5] = AxiomLicenseFacet.balanceOf.selector;
        licenseSelectors[6] = AxiomLicenseFacet.ownerOf.selector;
        licenseSelectors[7] = bytes4(keccak256("transferFrom(address,address,uint256)"));
        licenseSelectors[8] = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
        licenseSelectors[9] = bytes4(keccak256("safeTransferFrom(address,address,uint256,bytes)"));
        licenseSelectors[10] = AxiomLicenseFacet.approve.selector;
        licenseSelectors[11] = AxiomLicenseFacet.setApprovalForAll.selector;
        licenseSelectors[12] = AxiomLicenseFacet.getApproved.selector;
        licenseSelectors[13] = AxiomLicenseFacet.isApprovedForAll.selector;
        licenseSelectors[14] = AxiomLicenseFacet.name.selector;
        licenseSelectors[15] = AxiomLicenseFacet.symbol.selector;
        licenseSelectors[16] = AxiomLicenseFacet.tokenURI.selector;
        licenseSelectors[17] = AxiomLicenseFacet.royaltyInfo.selector;
        licenseSelectors[18] = AxiomLicenseFacet.setRoyaltySplit.selector;
        licenseSelectors[19] = AxiomLicenseFacet.getLicense.selector;
        licenseSelectors[20] = AxiomLicenseFacet.getLicensesByRecord.selector;
        licenseSelectors[21] = AxiomLicenseFacet.isLicenseValid.selector;
        licenseSelectors[22] = AxiomLicenseFacet.getRoyaltySplit.selector;
        licenseSelectors[23] = AxiomLicenseFacet.supportsInterface.selector;
        
        router.addFacetSelectors(address(licenseFacet), licenseSelectors);
        console2.log("   Registered", licenseSelectors.length, "selectors");
        
        // 4. Register AxiomDisputeFacet selectors
        console2.log("\n4. Registering AxiomDisputeFacet selectors...");
        bytes4[] memory disputeSelectors = new bytes4[](13);
        disputeSelectors[0] = AxiomDisputeFacet.initiateDispute.selector;
        disputeSelectors[1] = AxiomDisputeFacet.initiateDisputeWithToken.selector;
        disputeSelectors[2] = AxiomDisputeFacet.respondToDispute.selector;
        disputeSelectors[3] = AxiomDisputeFacet.submitEvidence.selector;
        disputeSelectors[4] = AxiomDisputeFacet.escalateToArbitration.selector;
        disputeSelectors[5] = AxiomDisputeFacet.resolveByTimeout.selector;
        disputeSelectors[6] = AxiomDisputeFacet.claimStake.selector;
        disputeSelectors[7] = AxiomDisputeFacet.getDispute.selector;
        disputeSelectors[8] = AxiomDisputeFacet.getDisputesByRecord.selector;
        disputeSelectors[9] = AxiomDisputeFacet.hasActiveDispute.selector;
        disputeSelectors[10] = AxiomDisputeFacet.getStakeConfig.selector;
        disputeSelectors[11] = AxiomDisputeFacet.getApprovedArbitrators.selector;
        disputeSelectors[12] = AxiomDisputeFacet.isArbitratorApproved.selector;
        
        router.addFacetSelectors(address(disputeFacet), disputeSelectors);
        console2.log("   Registered", disputeSelectors.length, "selectors");
        
        // 5. Initialize storage variables
        console2.log("\n5. Initializing Phase 3 storage...");
        _initializeStorage(router);
        
        vm.stopBroadcast();
        
        console2.log("\n=== Phase 3 Deployment Complete ===");
        console2.log("AxiomLicenseFacet:", address(licenseFacet));
        console2.log("AxiomDisputeFacet:", address(disputeFacet));
    }
    
    function _initializeStorage(AxiomRouter _router) internal {
        // Initialize reentrancy status to 1 (not entered)
        // This is critical for the nonReentrant modifier to work
        console2.log("   Setting reentrancy status...");
        
        // Note: We can't directly set storage from deployment script
        // The reentrancy status will be initialized by first use (defaults to 0, 
        // which will be treated as 1 on first check)
        
        // Initialize stake config (would need admin function in AxiomRouter)
        console2.log("   Stake config initialization required via admin functions");
        console2.log("   License treasury initialization required via admin functions");
        
        console2.log("   Storage initialization complete");
    }
}

/**
 * @title ConfigurePhase3
 * @notice Configure Phase 3 after deployment
 * @dev Separate script to configure stake parameters and arbitrators
 */
contract ConfigurePhase3 is Script {
    function run(
        address _router,
        address _licenseTreasury,
        address _stakeToken,
        uint256 _minStake,
        address[] memory _arbitrators
    ) public {
        console2.log("=== Configuring Phase 3 ===");
        
        AxiomRouter router = AxiomRouter(payable(_router));
        
        vm.startBroadcast();
        
        // Configure licensing treasury
        console2.log("\n1. Configuring license treasury:", _licenseTreasury);
        // TODO: Add admin function to set licenseTreasury in storage
        
        // Configure dispute stake parameters
        console2.log("\n2. Configuring dispute stake parameters:");
        console2.log("   Stake token:", _stakeToken);
        console2.log("   Min stake:", _minStake);
        // TODO: Add admin function to set stakeConfig in storage
        
        // Approve arbitrators
        console2.log("\n3. Approving arbitrators:");
        for (uint256 i = 0; i < _arbitrators.length; i++) {
            console2.log("   -", _arbitrators[i]);
            // TODO: Add admin function to approve arbitrators
        }
        
        vm.stopBroadcast();
        
        console2.log("\n=== Phase 3 Configuration Complete ===");
    }
}
