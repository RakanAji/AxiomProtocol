// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AxiomFacets} from "../../src/interfaces/AxiomFacets.sol";
import {AxiomTypesV2} from "../../src/libraries/AxiomTypesV2.sol";
import {AxiomTypes} from "../../src/libraries/AxiomTypes.sol";

/**
 * @title AxiomHandler
 * @notice Fuzzer proxy for Foundry invariant testing against the Diamond proxy.
 * @dev The handler constrains random inputs so the fuzzer explores deep execution
 *      paths rather than reverting on every call. It also tracks "ghost variables"
 *      — expected protocol state that the invariant assertions compare against
 *      actual on-chain state.
 *
 *      Architecture:
 *        Fuzzer → AxiomHandler.handler_*() → AxiomFacets(diamond).*(...)
 *
 *      Ghost Variables:
 *        ghost_totalETHStaked       — ETH currently locked in pending disputes
 *        ghost_totalProtocolFees    — cumulative protocol fees from claimStake
 *        ghost_totalLicensesMinted  — total license NFTs minted
 *        ghost_bannedAddresses      — set of addresses banned via handler
 */
contract AxiomHandler is Test {
    // ═══════════════════════════════════════════════════════════════════════════
    //                              STATE
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice The Diamond proxy cast to the unified interface
    AxiomFacets public diamond;

    /// @notice Admin address (has DEFAULT_ADMIN_ROLE)
    address public admin;

    /// @notice Treasury wallet address
    address public treasury;

    /// @notice Pool of actors the fuzzer can impersonate
    address[] public actors;

    // ─────────────────────── Constrained Input Pools ──────────────────────────

    /// @notice Record IDs that were successfully registered
    bytes32[] public registeredRecords;

    /// @notice Mapping to check if a record exists in our pool
    mapping(bytes32 => bool) public isRegistered;

    /// @notice Dispute IDs that are currently pending (awaiting timeout resolve)
    bytes32[] public pendingDisputes;

    /// @notice Mapping: disputeId => index in pendingDisputes (for removal)
    mapping(bytes32 => uint256) internal _pendingDisputeIndex;

    /// @notice Dispute IDs that are resolved (ready for claimStake)
    bytes32[] public resolvedDisputes;

    /// @notice Mapping: disputeId => challenger address
    mapping(bytes32 => address) public disputeChallenger;

    /// @notice Track which records have an active dispute (to avoid duplicate)
    mapping(bytes32 => bool) public hasActiveDisputeGhost;

    /// @notice License IDs created via handler
    uint256[] public createdLicenses;

    // ─────────────────────── Ghost Variables ──────────────────────────────────

    /// @notice Expected ETH locked in pending disputes (increased on initiate, decreased on claim)
    uint256 public ghost_totalETHStaked;

    /// @notice Expected cumulative protocol fees sent to treasury from claimStake
    uint256 public ghost_totalProtocolFees;

    /// @notice Expected total license NFTs minted via the handler
    uint256 public ghost_totalLicensesMinted;

    /// @notice Addresses that were banned via the handler
    address[] public ghost_bannedAddresses;
    mapping(address => bool) public ghost_isBanned;

    // ─────────────────────── Configuration ────────────────────────────────────

    /// @notice Minimum stake amount (mirrors stakeConfig.minStakeAmount)
    uint256 public minStake;

    /// @notice Protocol fee basis points (mirrors stakeConfig.protocolFeeBps)
    uint16 public protocolFeeBps;

    /// @notice Registration fee
    uint256 public baseFee;

    /// @notice Counter to generate unique hashes
    uint256 internal _nonce;

    // ═══════════════════════════════════════════════════════════════════════════
    //                           CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════════

    constructor(
        AxiomFacets _diamond,
        address _admin,
        address _treasury,
        address[] memory _actors,
        uint256 _minStake,
        uint16 _protocolFeeBps,
        uint256 _baseFee
    ) {
        diamond = _diamond;
        admin = _admin;
        treasury = _treasury;
        actors = _actors;
        minStake = _minStake;
        protocolFeeBps = _protocolFeeBps;
        baseFee = _baseFee;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          HANDLER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Register new content with a unique hash.
     * @dev Constrains: generates a collision-free hash using nonce.
     *      Ghost: no ghost update (registration fee goes to treasury via
     *      the TreasuryFacet's internal accounting, not tracked here).
     * @param _actorSeed Fuzzed seed to select an actor.
     */
    function handler_register(uint256 _actorSeed) external {
        address actor = _pickActor(_actorSeed);
        if (ghost_isBanned[actor]) return; // Banned actors can't register

        // Generate unique content hash
        bytes32 contentHash = keccak256(abi.encodePacked("content", _nonce++));

        // Prank as the actor and register
        vm.deal(actor, actor.balance + baseFee);
        vm.prank(actor);
        try diamond.register{value: baseFee}(contentHash, "ipfs://metadata") returns (bytes32 recordId) {
            registeredRecords.push(recordId);
            isRegistered[recordId] = true;
        } catch {
            // Silently skip if registration fails (e.g., rate limit)
        }
    }

    /**
     * @notice Create a license for a registered record, then purchase it.
     * @dev Constrains: picks from actually-registered records.
     *      Ghost: increments ghost_totalLicensesMinted.
     * @param _recordSeed Fuzzed seed to select a registered record.
     */
    function handler_createAndPurchaseLicense(uint256 _recordSeed) external {
        if (registeredRecords.length == 0) return;

        bytes32 recordId = _pickRecord(_recordSeed);
        
        // Use the record's issuer as the licensor
        AxiomTypes.AxiomRecord memory record = diamond.getRecord(recordId);
        address licensor = record.issuer;
        if (licensor == address(0)) return;

        // Create a free ETH license (price = 0, so no payment needed)
        vm.prank(licensor);
        try diamond.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.CC_BY,
            0,              // price = 0 (free)
            address(0),     // ETH
            250,            // 2.5% royalty
            0,              // perpetual
            false,          // not exclusive
            false,          // not sublicensable
            ""              // no custom terms
        ) returns (uint256 licenseId) {
            createdLicenses.push(licenseId);

            // Now purchase from a random actor
            address buyer = _pickActor(_recordSeed >> 128);
            if (ghost_isBanned[buyer]) return;

            vm.prank(buyer);
            try diamond.purchaseLicense(licenseId, 0) returns (uint256) {
                ghost_totalLicensesMinted++;
            } catch {
                // Purchase may fail (e.g., buyer == licensor issue, rate limit)
            }
        } catch {
            // License creation may fail
        }
    }

    /**
     * @notice Initiate a dispute against a registered record with ETH stake.
     * @dev Constrains: picks from registered records that have no active dispute.
     *      Ghost: increases ghost_totalETHStaked by minStake.
     * @param _recordSeed Fuzzed seed to select a registered record.
     */
    function handler_initiateDispute(uint256 _recordSeed) external {
        if (registeredRecords.length == 0) return;

        bytes32 recordId = _pickRecord(_recordSeed);
        
        // Skip if already has an active dispute
        if (hasActiveDisputeGhost[recordId]) return;

        address challenger = _pickActor(_recordSeed >> 64);
        if (ghost_isBanned[challenger]) return;
        
        // Ensure challenger has enough ETH
        vm.deal(challenger, challenger.balance + minStake);

        vm.prank(challenger);
        try diamond.initiateDispute{value: minStake}(
            recordId,
            AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT,
            "ipfs://evidence"
        ) returns (bytes32 disputeId) {
            // Track in pending pool
            _pendingDisputeIndex[disputeId] = pendingDisputes.length;
            pendingDisputes.push(disputeId);
            disputeChallenger[disputeId] = challenger;
            hasActiveDisputeGhost[recordId] = true;

            // Ghost: ETH is now locked in the Router
            ghost_totalETHStaked += minStake;
        } catch {
            // May fail due to stakeConfig.stakeToken != address(0) or other checks
        }
    }

    /**
     * @notice Resolve a pending dispute by timeout (challenger wins).
     * @dev Constrains: picks from pending disputes, warps past deadline.
     *      Ghost: moves dispute from pending to resolved pool.
     * @param _disputeSeed Fuzzed seed to select a pending dispute.
     */
    function handler_resolveDispute(uint256 _disputeSeed) external {
        if (pendingDisputes.length == 0) return;

        uint256 idx = _disputeSeed % pendingDisputes.length;
        bytes32 disputeId = pendingDisputes[idx];

        // Get dispute details to know the deadline
        AxiomTypesV2.Dispute memory dispute = diamond.getDispute(disputeId);
        
        // Warp past deadline
        vm.warp(uint256(dispute.deadline) + 1);

        try diamond.resolveByTimeout(disputeId) {
            // Move from pending to resolved
            _removePendingDispute(idx);
            resolvedDisputes.push(disputeId);
            hasActiveDisputeGhost[dispute.recordId] = false;
        } catch {
            // May fail if status changed
        }
    }

    /**
     * @notice Claim stake from a resolved dispute.
     * @dev Constrains: picks from resolved disputes, pranks as the winner.
     *      Ghost: decreases ghost_totalETHStaked, increases ghost_totalProtocolFees.
     * @param _disputeSeed Fuzzed seed to select a resolved dispute.
     */
    function handler_claimStake(uint256 _disputeSeed) external {
        if (resolvedDisputes.length == 0) return;

        uint256 idx = _disputeSeed % resolvedDisputes.length;
        bytes32 disputeId = resolvedDisputes[idx];

        AxiomTypesV2.Dispute memory dispute = diamond.getDispute(disputeId);

        // Already claimed (stakeAmount == 0)
        if (dispute.stakeAmount == 0) return;

        // Determine winner based on status
        address winner;
        if (dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_VALID) {
            winner = dispute.challenger;
        } else if (dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_INVALID) {
            // Need record owner — skip for simplicity if we can't determine
            try diamond.getRecord(dispute.recordId) returns (AxiomTypes.AxiomRecord memory record) {
                winner = record.issuer;
            } catch {
                return;
            }
        } else {
            return;
        }

        if (winner == address(0)) return;

        uint256 stakeAmount = dispute.stakeAmount;
        uint256 protocolFee = (stakeAmount * protocolFeeBps) / 10000;

        vm.prank(winner);
        try diamond.claimStake(disputeId) {
            // Ghost: ETH leaves the Router
            ghost_totalETHStaked -= stakeAmount;
            ghost_totalProtocolFees += protocolFee;
        } catch {
            // May fail if already claimed or unauthorized
        }
    }

    /**
     * @notice Ban a random actor.
     * @dev Ghost: adds address to ghost_bannedAddresses.
     * @param _actorSeed Fuzzed seed to select an actor.
     */
    function handler_banAddress(uint256 _actorSeed) external {
        address target = _pickActor(_actorSeed);
        if (ghost_isBanned[target]) return;

        vm.prank(admin);
        try diamond.banAddress(target, "Invariant test ban") {
            ghost_bannedAddresses.push(target);
            ghost_isBanned[target] = true;
        } catch {
            // May fail
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    function _pickActor(uint256 _seed) internal view returns (address) {
        return actors[_seed % actors.length];
    }

    function _pickRecord(uint256 _seed) internal view returns (bytes32) {
        return registeredRecords[_seed % registeredRecords.length];
    }

    /**
     * @dev Remove a pending dispute by swapping with last element and popping.
     */
    function _removePendingDispute(uint256 _idx) internal {
        uint256 lastIdx = pendingDisputes.length - 1;
        if (_idx != lastIdx) {
            bytes32 lastId = pendingDisputes[lastIdx];
            pendingDisputes[_idx] = lastId;
            _pendingDisputeIndex[lastId] = _idx;
        }
        pendingDisputes.pop();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          VIEW HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    function getRegisteredRecordsCount() external view returns (uint256) {
        return registeredRecords.length;
    }

    function getPendingDisputesCount() external view returns (uint256) {
        return pendingDisputes.length;
    }

    function getResolvedDisputesCount() external view returns (uint256) {
        return resolvedDisputes.length;
    }

    function getCreatedLicensesCount() external view returns (uint256) {
        return createdLicenses.length;
    }

    function getBannedAddressesCount() external view returns (uint256) {
        return ghost_bannedAddresses.length;
    }
}
