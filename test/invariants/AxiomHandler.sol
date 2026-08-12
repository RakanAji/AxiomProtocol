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
 *        ghost_totalETHStaked       — ETH locked in unresolved or unclaimed disputes
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

    /// @notice License NFT token IDs minted via handler
    uint256[] public purchasedTokenIds;

    // ─────────────────────── Ghost Variables ──────────────────────────────────

    /// @notice Expected ETH locked in unresolved or unclaimed disputes (increased on initiate, decreased on claim)
    uint256 public ghost_totalETHStaked;

    /// @notice Expected cumulative protocol fees sent to treasury from claimStake
    uint256 public ghost_totalProtocolFees;

    /// @notice Expected total license NFTs minted via the handler
    uint256 public ghost_totalLicensesMinted;

    /// @notice Per-action outcome accounting. Every handler call records exactly
    ///         one success, protocol revert, or constrained-input skip.
    mapping(bytes4 => uint256) public ghost_attemptsBySelector;
    mapping(bytes4 => uint256) public ghost_successesBySelector;
    mapping(bytes4 => uint256) public ghost_revertsBySelector;
    mapping(bytes4 => uint256) public ghost_skipsBySelector;

    uint256 public ghost_totalAttempts;
    uint256 public ghost_totalSuccesses;
    uint256 public ghost_totalReverts;
    uint256 public ghost_totalSkips;

    /// @notice Last caught revert, retained so a failing campaign is diagnosable.
    bytes4 public ghost_lastRevertSelector;
    bytes32 public ghost_lastRevertHash;

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

    event HandlerCallReverted(bytes4 indexed selector, bytes32 indexed reasonHash);

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
        bytes4 selector = this.handler_register.selector;
        _begin(selector);

        (address actor, bool foundActor) = _pickUnbannedActor(_actorSeed);
        if (!foundActor) {
            _skip(selector);
            return;
        }

        // Generate unique content hash
        bytes32 contentHash = keccak256(abi.encodePacked("content", _nonce++));

        // Prank as the actor and register
        vm.deal(actor, actor.balance + baseFee);
        vm.prank(actor);
        try diamond.register{value: baseFee}(contentHash, "ipfs://metadata") returns (bytes32 recordId) {
            registeredRecords.push(recordId);
            isRegistered[recordId] = true;
            _succeed(selector);
        } catch (bytes memory reason) {
            _reverted(selector, reason);
        }
    }

    /**
     * @notice Create a license for a registered record, then purchase it.
     * @dev Constrains: picks from actually-registered records.
     *      Ghost: increments ghost_totalLicensesMinted.
     * @param _recordSeed Fuzzed seed to select a registered record.
     */
    function handler_createAndPurchaseLicense(uint256 _recordSeed) external {
        bytes4 selector = this.handler_createAndPurchaseLicense.selector;
        _begin(selector);
        if (registeredRecords.length == 0) {
            _skip(selector);
            return;
        }

        bytes32 recordId = _pickRecord(_recordSeed);

        // Use the record's issuer as the licensor
        AxiomTypes.AxiomRecord memory record = diamond.getRecord(recordId);
        address licensor = record.issuer;
        if (licensor == address(0)) {
            _skip(selector);
            return;
        }

        // Create a free ETH license (price = 0, so no payment needed)
        vm.prank(licensor);
        try diamond.createLicense(
            recordId,
            AxiomTypesV2.LicenseType.CC_BY,
            0, // price = 0 (free)
            address(0), // ETH
            250, // 2.5% royalty
            0, // perpetual
            false, // not exclusive
            false, // not sublicensable
            "" // no custom terms
        ) returns (
            uint256 licenseId
        ) {
            createdLicenses.push(licenseId);

            // Now purchase from a random actor
            (address buyer, bool foundBuyer) = _pickUnbannedActor(_recordSeed >> 128);
            if (!foundBuyer) {
                _skip(selector);
                return;
            }

            vm.prank(buyer);
            try diamond.purchaseLicense(licenseId, 0) returns (uint256 tokenId) {
                purchasedTokenIds.push(tokenId);
                ghost_totalLicensesMinted++;
                _succeed(selector);
            } catch (bytes memory reason) {
                _reverted(selector, reason);
            }
        } catch (bytes memory reason) {
            _reverted(selector, reason);
        }
    }

    /**
     * @notice Initiate a dispute against a registered record with ETH stake.
     * @dev Constrains: picks from registered records that have no active dispute.
     *      Ghost: increases ghost_totalETHStaked by minStake.
     * @param _recordSeed Fuzzed seed to select a registered record.
     */
    function handler_initiateDispute(uint256 _recordSeed) external {
        bytes4 selector = this.handler_initiateDispute.selector;
        _begin(selector);
        if (registeredRecords.length == 0) {
            _skip(selector);
            return;
        }

        bytes32 recordId = _pickRecord(_recordSeed);
        AxiomTypes.AxiomRecord memory record = diamond.getRecord(recordId);

        // Skip if already has an active dispute
        if (hasActiveDisputeGhost[recordId]) {
            _skip(selector);
            return;
        }

        (address challenger, bool foundChallenger) = _pickUnbannedActorExcept(_recordSeed >> 64, record.issuer);
        if (!foundChallenger) {
            _skip(selector);
            return;
        }

        // Ensure challenger has enough ETH
        vm.deal(challenger, challenger.balance + minStake);

        vm.prank(challenger);
        try diamond.initiateDispute{value: minStake}(
            recordId, AxiomTypesV2.DisputeReason.COPYRIGHT_INFRINGEMENT, "ipfs://evidence"
        ) returns (
            bytes32 disputeId
        ) {
            // Track in pending pool
            _pendingDisputeIndex[disputeId] = pendingDisputes.length;
            pendingDisputes.push(disputeId);
            disputeChallenger[disputeId] = challenger;
            hasActiveDisputeGhost[recordId] = true;

            // Ghost: ETH is now locked in the Router
            ghost_totalETHStaked += minStake;
            _succeed(selector);
        } catch (bytes memory reason) {
            _reverted(selector, reason);
        }
    }

    /**
     * @notice Resolve a pending dispute by timeout (challenger wins).
     * @dev Constrains: picks from pending disputes, warps past deadline.
     *      Ghost: moves dispute from pending to resolved pool.
     * @param _disputeSeed Fuzzed seed to select a pending dispute.
     */
    function handler_resolveDispute(uint256 _disputeSeed) external {
        bytes4 selector = this.handler_resolveDispute.selector;
        _begin(selector);
        if (pendingDisputes.length == 0) {
            _skip(selector);
            return;
        }

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
            _succeed(selector);
        } catch (bytes memory reason) {
            _reverted(selector, reason);
        }
    }

    /**
     * @notice Claim stake from a resolved dispute.
     * @dev Constrains: picks from resolved disputes, pranks as the winner.
     *      Ghost: decreases ghost_totalETHStaked, increases ghost_totalProtocolFees.
     * @param _disputeSeed Fuzzed seed to select a resolved dispute.
     */
    function handler_claimStake(uint256 _disputeSeed) external {
        bytes4 selector = this.handler_claimStake.selector;
        _begin(selector);
        if (resolvedDisputes.length == 0) {
            _skip(selector);
            return;
        }

        uint256 idx = _disputeSeed % resolvedDisputes.length;
        bytes32 disputeId = resolvedDisputes[idx];

        AxiomTypesV2.Dispute memory dispute = diamond.getDispute(disputeId);

        // Already claimed (stakeAmount == 0)
        if (dispute.stakeAmount == 0) {
            _skip(selector);
            return;
        }

        // Determine winner based on status
        address winner;
        if (dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_VALID) {
            winner = dispute.challenger;
        } else if (dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_INVALID) {
            // Need record owner — skip for simplicity if we can't determine
            try diamond.getRecord(dispute.recordId) returns (AxiomTypes.AxiomRecord memory record) {
                winner = record.issuer;
            } catch (bytes memory reason) {
                _reverted(selector, reason);
                return;
            }
        } else {
            _skip(selector);
            return;
        }

        if (winner == address(0)) {
            _skip(selector);
            return;
        }

        uint256 stakeAmount = dispute.stakeAmount;
        uint256 protocolFee = (stakeAmount * protocolFeeBps) / 10000;

        vm.prank(winner);
        try diamond.claimStake(disputeId) {
            // Ghost: ETH leaves the Router
            ghost_totalETHStaked -= stakeAmount;
            ghost_totalProtocolFees += protocolFee;
            _removeResolvedDispute(idx);
            _succeed(selector);
        } catch (bytes memory reason) {
            _reverted(selector, reason);
        }
    }

    /**
     * @notice Ban a random actor.
     * @dev Ghost: adds address to ghost_bannedAddresses.
     * @param _actorSeed Fuzzed seed to select an actor.
     */
    function handler_banAddress(uint256 _actorSeed) external {
        bytes4 selector = this.handler_banAddress.selector;
        _begin(selector);
        address target = _pickActor(_actorSeed);
        if (ghost_isBanned[target]) {
            _skip(selector);
            return;
        }

        vm.prank(admin);
        try diamond.banAddress(target, "Invariant test ban") {
            ghost_bannedAddresses.push(target);
            ghost_isBanned[target] = true;
            _succeed(selector);
        } catch (bytes memory reason) {
            _reverted(selector, reason);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    function _pickActor(uint256 _seed) internal view returns (address) {
        return actors[_seed % actors.length];
    }

    function _pickUnbannedActor(uint256 _seed) internal view returns (address actor, bool found) {
        uint256 actorCount = actors.length;
        uint256 start = _seed % actorCount;
        for (uint256 i = 0; i < actorCount; i++) {
            actor = actors[(start + i) % actorCount];
            if (!ghost_isBanned[actor]) return (actor, true);
        }
    }

    function _pickUnbannedActorExcept(uint256 _seed, address _excluded)
        internal
        view
        returns (address actor, bool found)
    {
        uint256 actorCount = actors.length;
        uint256 start = _seed % actorCount;
        for (uint256 i = 0; i < actorCount; i++) {
            actor = actors[(start + i) % actorCount];
            if (actor != _excluded && !ghost_isBanned[actor]) return (actor, true);
        }
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

    function _removeResolvedDispute(uint256 _idx) internal {
        uint256 lastIdx = resolvedDisputes.length - 1;
        if (_idx != lastIdx) {
            resolvedDisputes[_idx] = resolvedDisputes[lastIdx];
        }
        resolvedDisputes.pop();
    }

    function _begin(bytes4 _selector) internal {
        ghost_totalAttempts++;
        ghost_attemptsBySelector[_selector]++;
    }

    function _succeed(bytes4 _selector) internal {
        ghost_totalSuccesses++;
        ghost_successesBySelector[_selector]++;
    }

    function _skip(bytes4 _selector) internal {
        ghost_totalSkips++;
        ghost_skipsBySelector[_selector]++;
    }

    function _reverted(bytes4 _selector, bytes memory _reason) internal {
        bytes32 reasonHash = keccak256(_reason);
        ghost_totalReverts++;
        ghost_revertsBySelector[_selector]++;
        ghost_lastRevertSelector = _selector;
        ghost_lastRevertHash = reasonHash;
        emit HandlerCallReverted(_selector, reasonHash);
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

    function getPurchasedTokenIdsCount() external view returns (uint256) {
        return purchasedTokenIds.length;
    }

    function getBannedAddressesCount() external view returns (uint256) {
        return ghost_bannedAddresses.length;
    }
}
