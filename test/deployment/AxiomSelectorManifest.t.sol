// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AxiomSelectorManifest} from "../../script/AxiomSelectorManifest.sol";
import {DeployPhase3} from "../../script/DeployPhase3.s.sol";
import {AxiomRouter} from "../../src/AxiomRouter.sol";
import {AxiomAccess} from "../../src/access/AxiomAccess.sol";
import {AxiomDIDRegistry} from "../../src/core/AxiomDIDRegistry.sol";
import {AxiomDisputeFacet} from "../../src/core/AxiomDisputeFacet.sol";
import {AxiomIdentity} from "../../src/core/AxiomIdentity.sol";
import {AxiomLicenseFacet} from "../../src/core/AxiomLicenseFacet.sol";
import {AxiomPrivacyFacet} from "../../src/core/AxiomPrivacyFacet.sol";
import {AxiomRegistry} from "../../src/core/AxiomRegistry.sol";
import {AxiomTreasury} from "../../src/core/AxiomTreasury.sol";
import {AxiomFacets} from "../../src/interfaces/AxiomFacets.sol";
import {AxiomTypesV2} from "../../src/libraries/AxiomTypesV2.sol";

contract AxiomSelectorManifestTest is Test {
    AxiomRouter internal router;

    address internal registryFacet;
    address internal treasuryFacet;
    address internal identityFacet;
    address internal accessFacet;
    address internal didFacet;
    address internal licenseFacet;
    address internal disputeFacet;
    address internal privacyFacet;

    function setUp() public {
        AxiomRouter implementation = new AxiomRouter();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation), abi.encodeCall(AxiomRouter.initialize, (address(this), address(0xFEE)))
        );
        router = AxiomRouter(payable(address(proxy)));

        registryFacet = address(new AxiomRegistry());
        treasuryFacet = address(new AxiomTreasury());
        identityFacet = address(new AxiomIdentity());
        accessFacet = address(new AxiomAccess());
        didFacet = address(new AxiomDIDRegistry());
        licenseFacet = address(new AxiomLicenseFacet());
        disputeFacet = address(new AxiomDisputeFacet());
        privacyFacet = address(new AxiomPrivacyFacet());

        _installManifest();
    }

    function test_manifestRoutesEverySelectorExactlyOnce() public view {
        bytes4[] memory seen = new bytes4[](AxiomSelectorManifest.totalFacetSelectors());
        uint256 count;

        count = _assertFacet(registryFacet, AxiomSelectorManifest.registrySelectors(), seen, count);
        count = _assertFacet(treasuryFacet, AxiomSelectorManifest.treasurySelectors(), seen, count);
        count = _assertFacet(identityFacet, AxiomSelectorManifest.identitySelectors(), seen, count);
        count = _assertFacet(accessFacet, AxiomSelectorManifest.accessSelectors(), seen, count);
        count = _assertFacet(didFacet, AxiomSelectorManifest.didSelectors(), seen, count);
        count = _assertFacet(licenseFacet, AxiomSelectorManifest.licenseSelectors(), seen, count);
        count = _assertFacet(disputeFacet, AxiomSelectorManifest.disputeSelectors(), seen, count);
        count = _assertFacet(privacyFacet, AxiomSelectorManifest.privacySelectors(), seen, count);

        assertEq(count, AxiomSelectorManifest.totalFacetSelectors(), "manifest count drift");
        assertEq(router.facetAddresses().length, 8, "unexpected facet count");
    }

    function test_manifestHasReviewedFacetCounts() public pure {
        assertEq(AxiomSelectorManifest.registrySelectors().length, 8);
        assertEq(AxiomSelectorManifest.treasurySelectors().length, 10);
        assertEq(AxiomSelectorManifest.identitySelectors().length, 7);
        assertEq(AxiomSelectorManifest.accessSelectors().length, 8);
        assertEq(AxiomSelectorManifest.didSelectors().length, 22);
        assertEq(AxiomSelectorManifest.licenseSelectors().length, 28);
        assertEq(AxiomSelectorManifest.disputeSelectors().length, 24);
        assertEq(AxiomSelectorManifest.privacySelectors().length, 14);
        assertEq(AxiomSelectorManifest.totalFacetSelectors(), 121);
    }

    function test_manifestDoesNotShadowRouterNativeSelectors() public view {
        assertEq(router.facetAddress(bytes4(keccak256("supportsInterface(bytes4)"))), address(0));
        assertEq(router.facetAddress(AxiomRouter.pause.selector), address(0));
        assertEq(router.facetAddress(AxiomRouter.unpause.selector), address(0));
    }

    function test_manifestExcludesRoadmapOnlyLicenseStubs() public view {
        assertEq(router.facetAddress(AxiomLicenseFacet.claimRoyalties.selector), address(0));
        assertEq(router.facetAddress(AxiomLicenseFacet.claimRoyaltiesToken.selector), address(0));
        assertEq(router.facetAddress(AxiomLicenseFacet.pendingRoyalties.selector), address(0));
        assertEq(router.facetAddress(AxiomLicenseFacet.createSublicense.selector), address(0));
        assertEq(router.facetAddress(AxiomLicenseFacet.purchaseSublicense.selector), address(0));
    }

    function test_manifestExcludesLegacyDisputeContentShortcut() public view {
        assertEq(router.facetAddress(AxiomAccess.disputeContent.selector), address(0));
    }

    function test_manifestExcludesUnusedDIDNonce() public view {
        assertEq(router.facetAddress(AxiomDIDRegistry.nonce.selector), address(0));
    }

    function test_reinstallingManifestIsIdempotent() public {
        _installManifest();
        assertEq(router.facetAddresses().length, 8, "reinstall duplicated facet addresses");
    }

    function test_disputeConfigurationIsAdminOnlyAndIdempotent() public {
        AxiomFacets diamond = AxiomFacets(payable(address(router)));
        AxiomTypesV2.StakeConfig memory config = _stakeConfig();

        vm.prank(address(0xBAD));
        vm.expectRevert("DisputeFacet: missing admin role");
        diamond.configureStakeConfig(config);

        diamond.configureStakeConfig(config);
        AxiomTypesV2.StakeConfig memory configured = diamond.getStakeConfig();
        assertEq(keccak256(abi.encode(configured)), keccak256(abi.encode(config)));

        diamond.configureStakeConfig(config);
        configured = diamond.getStakeConfig();
        assertEq(keccak256(abi.encode(configured)), keccak256(abi.encode(config)));
    }

    function test_phase3MigrationRequiresExplicitUnsafeLegacyAcknowledgement() public {
        DeployPhase3 migration = new DeployPhase3();
        vm.setEnv("AXIOM_ACK_UNSAFE_LEGACY_MIGRATION", "false");

        vm.expectRevert(DeployPhase3.LegacyMigrationNotAcknowledged.selector);
        migration.run(address(router));
    }

    function _installManifest() internal {
        router.addFacetSelectors(registryFacet, AxiomSelectorManifest.registrySelectors());
        router.addFacetSelectors(treasuryFacet, AxiomSelectorManifest.treasurySelectors());
        router.addFacetSelectors(identityFacet, AxiomSelectorManifest.identitySelectors());
        router.addFacetSelectors(accessFacet, AxiomSelectorManifest.accessSelectors());
        router.addFacetSelectors(didFacet, AxiomSelectorManifest.didSelectors());
        router.addFacetSelectors(licenseFacet, AxiomSelectorManifest.licenseSelectors());
        router.addFacetSelectors(disputeFacet, AxiomSelectorManifest.disputeSelectors());
        router.addFacetSelectors(privacyFacet, AxiomSelectorManifest.privacySelectors());
    }

    function _stakeConfig() internal pure returns (AxiomTypesV2.StakeConfig memory) {
        return AxiomTypesV2.StakeConfig({
            minStakeAmount: 0.01 ether,
            minAppealStake: 0.02 ether,
            stakeToken: address(0),
            protocolFeeBps: 500,
            rewardBps: 0,
            slashBps: 0,
            responsePeriod: 3 days,
            evidencePeriod: 3 days,
            appealPeriod: 3 days
        });
    }

    function _assertFacet(address expectedFacet, bytes4[] memory selectors, bytes4[] memory seen, uint256 count)
        internal
        view
        returns (uint256)
    {
        assertGt(expectedFacet.code.length, 0, "facet has no runtime code");
        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            assertEq(router.facetAddress(selector), expectedFacet, "selector routed to wrong facet");

            for (uint256 j = 0; j < count; ++j) {
                assertTrue(seen[j] != selector, "selector duplicated across manifest");
            }
            seen[count++] = selector;
        }
        return count;
    }
}
