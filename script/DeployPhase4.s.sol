// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AxiomRouter} from "../src/AxiomRouter.sol";
import {AxiomFacets} from "../src/interfaces/AxiomFacets.sol";
import {AxiomTypesV2} from "../src/libraries/AxiomTypesV2.sol";
import {AxiomRegistry} from "../src/core/AxiomRegistry.sol";
import {AxiomTreasury} from "../src/core/AxiomTreasury.sol";
import {AxiomIdentity} from "../src/core/AxiomIdentity.sol";
import {AxiomAccess} from "../src/access/AxiomAccess.sol";
import {AxiomDIDRegistry} from "../src/core/AxiomDIDRegistry.sol";
import {AxiomLicenseFacet} from "../src/core/AxiomLicenseFacet.sol";
import {AxiomDisputeFacet} from "../src/core/AxiomDisputeFacet.sol";
import {AxiomPrivacyFacet} from "../src/core/AxiomPrivacyFacet.sol";
import {AxiomSelectorManifest} from "./AxiomSelectorManifest.sol";

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
    error FacetCountMismatch(uint256 expected, uint256 actual);
    error NativeSelectorCollision(bytes4 selector, address facet);
    error SelectorRoutingMismatch(bytes4 selector, address expected, address actual);
    error StakeConfigMismatch();
    error ArbitratorConfigurationMismatch(address arbitrator);
    error VerifierConfigurationMismatch(address verifier);
    error EnvironmentValueOutOfRange(string name, uint256 value);
    error AdminSignerMismatch(address configuredAdmin, address broadcastSigner);

    function run() public returns (AxiomRouter router) {
        // Resolve the actual signer selected by `--sender`, `--account`, or
        // the private key before using it as the initial admin. Reading
        // `msg.sender` before startBroadcast() falls back to Foundry's default
        // caller and can silently strand the freshly deployed router.
        vm.startBroadcast();
        (, address broadcaster,) = vm.readCallers();
        address admin = vm.envOr("ADMIN_ADDRESS", broadcaster);
        if (admin != broadcaster) revert AdminSignerMismatch(admin, broadcaster);
        address treasury = vm.envOr("TREASURY_ADDRESS", admin);

        console2.log("=== Axiom Protocol: Phase 4 Master Deployment ===");
        console2.log("Admin:", admin);
        console2.log("Treasury:", treasury);

        // Step 1: Deploy Router Proxy
        router = _deployRouter(admin, treasury);

        // Step 2-3: Deploy & wire all facets (split into helpers to stay under stack limit)
        _deployAndWireCoreFacets(router);
        _deployAndWireBusinessFacets(router);
        _deployAndWirePrivacyFacet(router);
        AxiomTypesV2.StakeConfig memory stakeConfig = _configuredStakeConfig();
        AxiomFacets diamond = AxiomFacets(payable(address(router)));
        diamond.configureStakeConfig(stakeConfig);

        address arbitrator = vm.envOr("AXIOM_ARBITRATOR", address(0));
        if (arbitrator != address(0)) {
            diamond.setArbitrator(arbitrator, true);
        }

        address zkVerifier = vm.envOr("AXIOM_ZK_VERIFIER", address(0));
        bool approveZKVerifier = vm.envOr("AXIOM_APPROVE_ZK_VERIFIER", false);
        if (zkVerifier != address(0)) {
            diamond.setZKVerifier(zkVerifier);
            if (approveZKVerifier) {
                diamond.approveZKVerifierForProduction();
            }
        } else if (approveZKVerifier) {
            revert VerifierConfigurationMismatch(address(0));
        }

        _assertDeployment(router, stakeConfig, arbitrator, zkVerifier, approveZKVerifier);

        vm.stopBroadcast();

        console2.log("\n=== Phase 4 Deployment Complete ===");
        console2.log("Router Proxy:", address(router));
    }

    // ──────────────────────────────────────────────────────────
    //  Router Deployment
    // ──────────────────────────────────────────────────────────

    function _deployRouter(address _admin, address _treasury) internal returns (AxiomRouter) {
        console2.log("\n[1/10] Deploying AxiomRouter implementation...");
        AxiomRouter routerImpl = new AxiomRouter();

        console2.log("[2/10] Deploying ERC1967 Proxy...");
        bytes memory initData = abi.encodeWithSelector(AxiomRouter.initialize.selector, _admin, _treasury);
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
        _installFacet(_router, address(facet), AxiomSelectorManifest.registrySelectors());
        console2.log("[4/10] Wired AxiomRegistry");
    }

    function _wireTreasury(AxiomRouter _router) internal {
        AxiomTreasury facet = new AxiomTreasury();
        console2.log("   AxiomTreasury:", address(facet));
        _installFacet(_router, address(facet), AxiomSelectorManifest.treasurySelectors());
        console2.log("[5/10] Wired AxiomTreasury");
    }

    function _wireIdentity(AxiomRouter _router) internal {
        AxiomIdentity facet = new AxiomIdentity();
        console2.log("   AxiomIdentity:", address(facet));
        _installFacet(_router, address(facet), AxiomSelectorManifest.identitySelectors());
        console2.log("[6/10] Wired AxiomIdentity");
    }

    function _wireAccess(AxiomRouter _router) internal {
        AxiomAccess facet = new AxiomAccess();
        console2.log("   AxiomAccess:", address(facet));
        _installFacet(_router, address(facet), AxiomSelectorManifest.accessSelectors());
        console2.log("[7/10] Wired AxiomAccess");
    }

    function _wireDID(AxiomRouter _router) internal {
        AxiomDIDRegistry facet = new AxiomDIDRegistry();
        console2.log("   AxiomDIDRegistry:", address(facet));
        _installFacet(_router, address(facet), AxiomSelectorManifest.didSelectors());
        console2.log("[8/10] Wired AxiomDIDRegistry");
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
        _installFacet(_router, address(facet), AxiomSelectorManifest.licenseSelectors());
        console2.log("   Wired AxiomLicenseFacet");
    }

    function _wireDispute(AxiomRouter _router) internal {
        AxiomDisputeFacet facet = new AxiomDisputeFacet();
        console2.log("   AxiomDisputeFacet:", address(facet));
        _installFacet(_router, address(facet), AxiomSelectorManifest.disputeSelectors());
        console2.log("   Wired AxiomDisputeFacet");
    }

    // ──────────────────────────────────────────────────────────
    //  Privacy Facet
    // ──────────────────────────────────────────────────────────

    function _deployAndWirePrivacyFacet(AxiomRouter _router) internal {
        console2.log("\n[10/10] Wiring AxiomPrivacyFacet...");
        AxiomPrivacyFacet facet = new AxiomPrivacyFacet();
        console2.log("   AxiomPrivacyFacet:", address(facet));

        _installFacet(_router, address(facet), AxiomSelectorManifest.privacySelectors());
        console2.log("   Wired AxiomPrivacyFacet");
    }

    function _installFacet(AxiomRouter _router, address _facet, bytes4[] memory _selectors) internal {
        _router.addFacetSelectors(_facet, _selectors);
        for (uint256 i = 0; i < _selectors.length; ++i) {
            address actual = _router.facetAddress(_selectors[i]);
            if (actual != _facet) {
                revert SelectorRoutingMismatch(_selectors[i], _facet, actual);
            }
        }
    }

    function _configuredStakeConfig() internal view returns (AxiomTypesV2.StakeConfig memory config) {
        config = AxiomTypesV2.StakeConfig({
            minStakeAmount: vm.envOr("AXIOM_MIN_STAKE", uint256(0.01 ether)),
            minAppealStake: vm.envOr("AXIOM_MIN_APPEAL_STAKE", uint256(0.02 ether)),
            stakeToken: vm.envOr("AXIOM_STAKE_TOKEN", address(0)),
            protocolFeeBps: _envUint16("AXIOM_PROTOCOL_FEE_BPS", 500),
            rewardBps: 0,
            slashBps: 0,
            responsePeriod: _envUint40("AXIOM_RESPONSE_PERIOD", 3 days),
            evidencePeriod: _envUint40("AXIOM_EVIDENCE_PERIOD", 3 days),
            appealPeriod: _envUint40("AXIOM_APPEAL_PERIOD", 3 days)
        });
    }

    function _envUint16(string memory _name, uint256 _defaultValue) internal view returns (uint16) {
        uint256 value = vm.envOr(_name, _defaultValue);
        if (value > type(uint16).max) revert EnvironmentValueOutOfRange(_name, value);
        return uint16(value);
    }

    function _envUint40(string memory _name, uint256 _defaultValue) internal view returns (uint40) {
        uint256 value = vm.envOr(_name, _defaultValue);
        if (value > type(uint40).max) revert EnvironmentValueOutOfRange(_name, value);
        return uint40(value);
    }

    function _assertDeployment(
        AxiomRouter _router,
        AxiomTypesV2.StakeConfig memory _expectedConfig,
        address _arbitrator,
        address _zkVerifier,
        bool _zkVerifierApproved
    ) internal view {
        address[] memory facets = _router.facetAddresses();
        if (facets.length != 8) {
            revert FacetCountMismatch(8, facets.length);
        }

        bytes4[3] memory nativeSelectors =
            [bytes4(keccak256("supportsInterface(bytes4)")), AxiomRouter.pause.selector, AxiomRouter.unpause.selector];
        for (uint256 i = 0; i < nativeSelectors.length; ++i) {
            address routedFacet = _router.facetAddress(nativeSelectors[i]);
            if (routedFacet != address(0)) {
                revert NativeSelectorCollision(nativeSelectors[i], routedFacet);
            }
        }

        AxiomFacets diamond = AxiomFacets(payable(address(_router)));
        AxiomTypesV2.StakeConfig memory actual = diamond.getStakeConfig();
        if (keccak256(abi.encode(actual)) != keccak256(abi.encode(_expectedConfig))) {
            revert StakeConfigMismatch();
        }
        if (_arbitrator != address(0) && !diamond.isArbitratorApproved(_arbitrator)) {
            revert ArbitratorConfigurationMismatch(_arbitrator);
        }
        if (diamond.getZKVerifier() != _zkVerifier || diamond.isZKVerifierProductionApproved() != _zkVerifierApproved) {
            revert VerifierConfigurationMismatch(_zkVerifier);
        }
    }
}
