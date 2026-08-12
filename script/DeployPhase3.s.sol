// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {AxiomRouter} from "../src/AxiomRouter.sol";
import {AxiomLicenseFacet} from "../src/core/AxiomLicenseFacet.sol";
import {AxiomDisputeFacet} from "../src/core/AxiomDisputeFacet.sol";
import {AxiomFacets} from "../src/interfaces/AxiomFacets.sol";
import {AxiomTypesV2} from "../src/libraries/AxiomTypesV2.sol";
import {AxiomSelectorManifest} from "./AxiomSelectorManifest.sol";

/**
 * @title DeployPhase3
 * @notice Explicitly acknowledged legacy migration that installs the current License and Dispute facets.
 * @dev Fresh deployments should use DeployPhase4. This script is safe only for
 *      a router with no existing records, licenses, or disputes. Appended global
 *      indexes and native-stake escrow accounting cannot be reconstructed by a
 *      facet upgrade. A populated router requires a separately audited state
 *      migration. The broadcasting signer must hold DEFAULT_ADMIN_ROLE on
 *      `_router`, and configuration is a separate transaction through
 *      ConfigurePhase3.
 */
contract DeployPhase3 is Script {
    error LegacyMigrationNotAcknowledged();
    error SelectorRoutingMismatch(bytes4 selector, address expected, address actual);

    function run(address _router) public returns (address licenseFacet, address disputeFacet) {
        if (!vm.envOr("AXIOM_ACK_UNSAFE_LEGACY_MIGRATION", false)) {
            revert LegacyMigrationNotAcknowledged();
        }

        AxiomRouter router = AxiomRouter(payable(_router));

        vm.startBroadcast();
        licenseFacet = address(new AxiomLicenseFacet());
        disputeFacet = address(new AxiomDisputeFacet());
        _installFacet(router, licenseFacet, AxiomSelectorManifest.licenseSelectors());
        _installFacet(router, disputeFacet, AxiomSelectorManifest.disputeSelectors());
        vm.stopBroadcast();

        console2.log("AxiomLicenseFacet:", licenseFacet);
        console2.log("AxiomDisputeFacet:", disputeFacet);
        console2.log("Legacy migration was explicitly acknowledged; verify the router had no populated state.");
        console2.log("Run ConfigurePhase3 with reviewed network parameters before enabling disputes.");
    }

    function _installFacet(AxiomRouter _router, address _facet, bytes4[] memory _selectors) internal {
        _router.addFacetSelectors(_facet, _selectors);
        for (uint256 i = 0; i < _selectors.length; i++) {
            address actual = _router.facetAddress(_selectors[i]);
            if (actual != _facet) revert SelectorRoutingMismatch(_selectors[i], _facet, actual);
        }
    }
}

/**
 * @title ConfigurePhase3
 * @notice Applies License/Dispute configuration through production admin APIs.
 * @dev Re-running with the same values is idempotent, including arbitrator list membership.
 */
contract ConfigurePhase3 is Script {
    error ConfigurationMismatch();

    function run(
        address _router,
        address _licenseTreasury,
        address _stakeToken,
        uint256 _minStake,
        address[] memory _arbitrators
    ) public {
        AxiomFacets diamond = AxiomFacets(payable(_router));
        AxiomTypesV2.StakeConfig memory config = AxiomTypesV2.StakeConfig({
            minStakeAmount: _minStake,
            minAppealStake: _minStake,
            stakeToken: _stakeToken,
            protocolFeeBps: 500,
            rewardBps: 0,
            slashBps: 0,
            responsePeriod: 3 days,
            evidencePeriod: 3 days,
            appealPeriod: 3 days
        });

        vm.startBroadcast();
        diamond.setLicenseTreasury(_licenseTreasury);
        diamond.configureStakeConfig(config);
        for (uint256 i = 0; i < _arbitrators.length; i++) {
            diamond.setArbitrator(_arbitrators[i], true);
        }
        vm.stopBroadcast();

        if (
            diamond.getLicenseTreasury() != _licenseTreasury
                || keccak256(abi.encode(diamond.getStakeConfig())) != keccak256(abi.encode(config))
        ) {
            revert ConfigurationMismatch();
        }
        for (uint256 i = 0; i < _arbitrators.length; i++) {
            if (!diamond.isArbitratorApproved(_arbitrators[i])) revert ConfigurationMismatch();
        }
    }
}
