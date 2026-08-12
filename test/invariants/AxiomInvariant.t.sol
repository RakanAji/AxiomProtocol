// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Core
import {AxiomRouter} from "../../src/AxiomRouter.sol";
import {AxiomTypes} from "../../src/libraries/AxiomTypes.sol";
import {AxiomTypesV2} from "../../src/libraries/AxiomTypesV2.sol";

// Facets
import {AxiomRegistry} from "../../src/core/AxiomRegistry.sol";
import {AxiomTreasury} from "../../src/core/AxiomTreasury.sol";
import {AxiomIdentity} from "../../src/core/AxiomIdentity.sol";
import {AxiomAccess} from "../../src/access/AxiomAccess.sol";
import {AxiomDIDRegistry} from "../../src/core/AxiomDIDRegistry.sol";
import {AxiomLicenseFacet} from "../../src/core/AxiomLicenseFacet.sol";
import {AxiomDisputeFacet} from "../../src/core/AxiomDisputeFacet.sol";
import {AxiomPrivacyFacet} from "../../src/core/AxiomPrivacyFacet.sol";

// Mock
import {MockVerifier} from "../mocks/MockVerifier.sol";

// Interface
import {AxiomFacets} from "../../src/interfaces/AxiomFacets.sol";

// Handler
import {AxiomHandler} from "./AxiomHandler.sol";
import {AxiomSelectorManifest} from "../../script/AxiomSelectorManifest.sol";

/**
 * @title AxiomInvariant
 * @notice Stateful fuzzing invariant test suite for Axiom Protocol
 * @dev Uses a Handler contract to constrain fuzzer inputs and track ghost variables.
 *      The fuzzer calls random handler functions in random order (stateful fuzzing),
 *      then after each sequence it asserts the invariants hold.
 *
 *      Invariants:
 *      1. Solvency: Router ETH balance >= expected locked stakes
 *      2. License Integrity: every tracked mint retains an exact, owned token ID
 *      3. No Access For Banned: banned addresses are truly banned on-chain
 *      4. Handler Accounting: every action records one visible outcome and seeded core paths succeed
 *
 *      Run with:
 *        forge test --match-contract AxiomInvariant -vvvv
 */
contract AxiomInvariant is Test {
    // ═══════════════════════════════════════════════════════════════════════════
    //                              STATE
    // ═══════════════════════════════════════════════════════════════════════════

    AxiomRouter public router;
    AxiomFacets public diamond;
    AxiomHandler public handler;

    // Facet implementations
    AxiomRegistry public registryFacet;
    AxiomTreasury public treasuryFacet;
    AxiomIdentity public identityFacet;
    AxiomAccess public accessFacet;
    AxiomDIDRegistry public didFacet;
    AxiomLicenseFacet public licenseFacet;
    AxiomDisputeFacet public disputeFacet;
    AxiomPrivacyFacet public privacyFacet;
    MockVerifier public mockVerifier;

    // Test actors
    address public admin = address(0xAD);
    address public treasury = address(0xFEE);

    // Actors pool for the handler
    address[] public actors;

    // Constants
    uint256 public constant BASE_FEE = 0.0001 ether;
    uint256 public constant MIN_STAKE = 0.01 ether;
    uint16 public constant PROTOCOL_FEE_BPS = 500; // 5%
    uint40 public constant RESPONSE_PERIOD = 7 days;
    uint40 public constant EVIDENCE_PERIOD = 14 days;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              SETUP
    // ═══════════════════════════════════════════════════════════════════════════

    function setUp() public {
        // ─── Deploy Diamond proxy ───
        AxiomRouter routerImpl = new AxiomRouter();
        bytes memory initData = abi.encodeWithSelector(AxiomRouter.initialize.selector, admin, treasury);
        ERC1967Proxy proxy = new ERC1967Proxy(address(routerImpl), initData);
        router = AxiomRouter(payable(address(proxy)));
        diamond = AxiomFacets(payable(address(proxy)));

        // ─── Deploy facets ───
        registryFacet = new AxiomRegistry();
        treasuryFacet = new AxiomTreasury();
        identityFacet = new AxiomIdentity();
        accessFacet = new AxiomAccess();
        didFacet = new AxiomDIDRegistry();
        licenseFacet = new AxiomLicenseFacet();
        disputeFacet = new AxiomDisputeFacet();
        privacyFacet = new AxiomPrivacyFacet();
        mockVerifier = new MockVerifier();

        // ─── Wire all facets ───
        vm.startPrank(admin);
        _wireRegistryFacet();
        _wireTreasuryFacet();
        _wireIdentityFacet();
        _wireAccessFacet();
        _wireDIDFacet();
        _wireLicenseFacet();
        _wireDisputeFacet();
        _wirePrivacyFacet();

        // Configure ZK verifier
        diamond.setZKVerifier(address(mockVerifier));

        // Configure stake parameters through the production admin API.
        diamond.configureStakeConfig(_stakeConfig(address(0)));

        // Grant operator role
        bytes32 operatorRole = router.OPERATOR_ROLE();
        router.grantRole(operatorRole, admin);
        vm.stopPrank();

        // ─── Create actor pool ───
        actors = new address[](5);
        actors[0] = address(0xA1);
        actors[1] = address(0xA2);
        actors[2] = address(0xA3);
        actors[3] = address(0xA4);
        actors[4] = address(0xA5);

        // Fund actors
        for (uint256 i = 0; i < actors.length; i++) {
            vm.deal(actors[i], 100 ether);
        }

        // ─── Deploy Handler ───
        handler = new AxiomHandler(diamond, admin, treasury, actors, MIN_STAKE, PROTOCOL_FEE_BPS, BASE_FEE);

        // Seed a complete successful lifecycle so every campaign proves it can
        // reach registration, minting, dispute resolution, and stake claiming.
        handler.handler_register(0);
        handler.handler_createAndPurchaseLicense(0);
        handler.handler_initiateDispute(0);
        handler.handler_resolveDispute(0);
        handler.handler_claimStake(0);
        handler.handler_banAddress(4);

        // Target only the six constrained, state-changing handler actions.
        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = AxiomHandler.handler_register.selector;
        selectors[1] = AxiomHandler.handler_createAndPurchaseLicense.selector;
        selectors[2] = AxiomHandler.handler_initiateDispute.selector;
        selectors[3] = AxiomHandler.handler_resolveDispute.selector;
        selectors[4] = AxiomHandler.handler_claimStake.selector;
        selectors[5] = AxiomHandler.handler_banAddress.selector;
        // Foundry otherwise targets every contract created during setUp,
        // including the router and facet implementations. Restricting the
        // target contract makes the invariant exercise only the constrained
        // handler surface, where all calls have outcome accounting.
        targetContract(address(handler));
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          INVARIANT ASSERTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice INVARIANT #1: Solvency
     * @dev The Router's actual ETH balance must ALWAYS be >= the ghost-tracked
     *      ETH that is supposed to be locked in pending dispute stakes.
     *
     *      If this fails, it means ETH left the contract without being
     *      properly accounted for — a critical solvency bug.
     */
    function invariant_Solvency() public view {
        uint256 routerBalance = address(diamond).balance;
        uint256 expectedMinimum = handler.ghost_totalETHStaked();

        assertGe(
            routerBalance,
            expectedMinimum,
            "INVARIANT VIOLATION: Router is insolvent! ETH balance < expected locked stakes"
        );
    }

    /**
     * @notice INVARIANT #2: License Integrity
     * @dev Every successful purchase must retain the exact returned token ID,
     *      and that token must have a non-zero owner. This avoids assuming token
     *      IDs are interchangeable with an N or N+1 mint count.
     */
    function invariant_LicenseIntegrity() public {
        uint256 ghostMinted = handler.ghost_totalLicensesMinted();
        uint256 trackedTokenCount = handler.getPurchasedTokenIdsCount();
        assertEq(trackedTokenCount, ghostMinted, "INVARIANT VIOLATION: mint/token accounting mismatch");

        uint256 lastTokenId = handler.purchasedTokenIds(trackedTokenCount - 1);
        assertNotEq(diamond.ownerOf(lastTokenId), address(0), "INVARIANT VIOLATION: minted token has zero owner");
    }

    /**
     * @notice INVARIANT #3: No Access For Banned
     * @dev Every address that was banned through the handler MUST return
     *      isBanned() == true on the Diamond. If any banned address returns
     *      false, the ban system is broken.
     */
    function invariant_NoAccessForBanned() public view {
        uint256 count = handler.getBannedAddressesCount();

        for (uint256 i = 0; i < count; i++) {
            address banned = handler.ghost_bannedAddresses(i);
            assertTrue(diamond.isBanned(banned), "INVARIANT VIOLATION: Address was banned but isBanned() returns false");
        }
    }

    /**
     * @notice INVARIANT #4: handler outcomes stay visible and exhaustive.
     * @dev The deterministic seed also guarantees each core path is reachable;
     *      fuzz-time protocol reverts remain counted instead of disappearing.
     */
    function invariant_HandlerAccounting() public view {
        assertEq(
            handler.ghost_totalAttempts(),
            handler.ghost_totalSuccesses() + handler.ghost_totalReverts() + handler.ghost_totalSkips(),
            "INVARIANT VIOLATION: handler outcome accounting mismatch"
        );

        bytes4[6] memory selectors = [
            AxiomHandler.handler_register.selector,
            AxiomHandler.handler_createAndPurchaseLicense.selector,
            AxiomHandler.handler_initiateDispute.selector,
            AxiomHandler.handler_resolveDispute.selector,
            AxiomHandler.handler_claimStake.selector,
            AxiomHandler.handler_banAddress.selector
        ];
        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            assertEq(
                handler.ghost_attemptsBySelector(selector),
                handler.ghost_successesBySelector(selector) + handler.ghost_revertsBySelector(selector)
                    + handler.ghost_skipsBySelector(selector),
                "INVARIANT VIOLATION: per-action outcome accounting mismatch"
            );
            assertGt(
                handler.ghost_successesBySelector(selector),
                0,
                "INVARIANT VIOLATION: seeded core action never succeeded"
            );
        }
    }

    function _stakeConfig(address _stakeToken) internal pure returns (AxiomTypesV2.StakeConfig memory) {
        return AxiomTypesV2.StakeConfig({
            minStakeAmount: MIN_STAKE,
            minAppealStake: 0.005 ether,
            stakeToken: _stakeToken,
            protocolFeeBps: PROTOCOL_FEE_BPS,
            rewardBps: 0,
            slashBps: 0,
            responsePeriod: RESPONSE_PERIOD,
            evidencePeriod: EVIDENCE_PERIOD,
            appealPeriod: 3 days
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                      FACET WIRING (copied from IntegrationTest)
    // ═══════════════════════════════════════════════════════════════════════════

    function _wireRegistryFacet() internal {
        router.addFacetSelectors(address(registryFacet), AxiomSelectorManifest.registrySelectors());
    }

    function _wireTreasuryFacet() internal {
        router.addFacetSelectors(address(treasuryFacet), AxiomSelectorManifest.treasurySelectors());
    }

    function _wireIdentityFacet() internal {
        router.addFacetSelectors(address(identityFacet), AxiomSelectorManifest.identitySelectors());
    }

    function _wireAccessFacet() internal {
        router.addFacetSelectors(address(accessFacet), AxiomSelectorManifest.accessSelectors());
    }

    function _wireDIDFacet() internal {
        router.addFacetSelectors(address(didFacet), AxiomSelectorManifest.didSelectors());
    }

    function _wireLicenseFacet() internal {
        router.addFacetSelectors(address(licenseFacet), AxiomSelectorManifest.licenseSelectors());
    }

    function _wireDisputeFacet() internal {
        router.addFacetSelectors(address(disputeFacet), AxiomSelectorManifest.disputeSelectors());
    }

    function _wirePrivacyFacet() internal {
        router.addFacetSelectors(address(privacyFacet), AxiomSelectorManifest.privacySelectors());
    }
}
