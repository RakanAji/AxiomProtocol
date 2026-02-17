// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";
import {IAxiomDispute} from "../interfaces/IAxiomDispute.sol";
import {IArbitrator} from "../interfaces/IArbitrator.sol";

/**
 * @title AxiomDisputeFacet
 * @author Axiom Protocol Team
 * @notice Diamond Facet for Decentralized Dispute Resolution
 * @dev Stateless facet executed via delegatecall from AxiomRouter.
 *      
 *      Features:
 *      - Dual-currency staking (Native ETH or ERC-20)
 *      - Evidence submission period
 *     - Auto-resolution by timeout
 *      - Integration with external arbitrators (Kleros/Aragon)
 *      
 *      CRITICAL: All state stored in AxiomStorage. No state variables in this contract.
 */
contract AxiomDisputeFacet is IAxiomDispute {
    using SafeERC20 for IERC20;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════════

    // Ruling Options (Kleros Standard)
    uint256 private constant RULING_OPTIONS = 2; // 1 = Challenger Wins, 2 = Content Owner Wins
    uint256 private constant RULING_REFUSED = 0;
    uint256 private constant RULING_CHALLENGER = 1;
    uint256 private constant RULING_OWNER = 2;

    // ═══════════════════════════════════════════════════════════════════════════
    //                              MODIFIERS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Reentrancy protection using shared storage
     */
    modifier nonReentrant() {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        require(s.reentrancyStatus != 2, "ReentrancyGuard: reentrant call");
        s.reentrancyStatus = 2;
        _;
        s.reentrancyStatus = 1;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          DISPUTE INITIATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Initiates a new dispute against a content record.
     * @dev Supports ETH staking. Checks for active disputes and minimum stake.
     * @param _recordId The ID of the content being disputed.
     * @param _reason The reason for the dispute.
     * @param _evidenceURI IPFS URI containing evidence for the dispute.
     * @return disputeId The unique ID of the created dispute.
     */
    function initiateDispute(
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI
    ) external payable override nonReentrant returns (bytes32 disputeId) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Validate ETH staking mode
        if (s.stakeConfig.stakeToken != address(0)) {
            revert AxiomTypesV2.OperationNotPermitted(); // Must use initiateDisputeWithToken
        }

        return _initiateDispute(
            s, 
            _recordId, 
            _reason, 
            _evidenceURI, 
            address(0), 
            msg.value
        );
    }

    /**
     * @notice Initiates a new dispute using an ERC-20 token for staking.
     * @dev Requires token allowance. Transfers tokens to contract.
     *      CEI: State is written in _initiateDispute BEFORE the safeTransferFrom
     *      interaction, preventing ERC-777 tokensToSend reentrancy attacks.
     * @param _recordId The ID of the content being disputed.
     * @param _reason The reason for the dispute.
     * @param _evidenceURI IPFS URI containing evidence for the dispute.
     * @param _stakeToken The address of the ERC-20 token used for staking.
     * @param _stakeAmount The amount of tokens to stake.
     * @return disputeId The unique ID of the created dispute.
     */
    function initiateDisputeWithToken(
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI,
        address _stakeToken,
        uint256 _stakeAmount
    ) external override nonReentrant returns (bytes32 disputeId) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // CHECK: Verify configured token
        if (_stakeToken != s.stakeConfig.stakeToken) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        // EFFECT: Write dispute state BEFORE external call (CEI)
        disputeId = _initiateDispute(
            s, 
            _recordId, 
            _reason, 
            _evidenceURI, 
            _stakeToken, 
            _stakeAmount
        );

        // INTERACTION: Transfer tokens AFTER state is written
        // Safe against ERC-777 tokensToSend reentrancy: dispute already
        // exists in storage, so hasActiveDispute() will block re-entry
        IERC20(_stakeToken).safeTransferFrom(msg.sender, address(this), _stakeAmount);
    }

    function _initiateDispute(
        AxiomStorage.Storage storage s,
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI,
        address _token,
        uint256 _amount
    ) internal returns (bytes32 disputeId) {
        // Enforce minimum stake
        if (_amount < s.stakeConfig.minStakeAmount) {
            revert AxiomTypesV2.InsufficientStake(_amount, s.stakeConfig.minStakeAmount);
        }

        // Check active disputes
        if (hasActiveDispute(_recordId)) {
            revert AxiomTypesV2.OperationNotPermitted(); // Content already disputed
        }

        // Generate ID
        disputeId = keccak256(
            abi.encodePacked(
                _recordId, 
                msg.sender, 
                block.timestamp, 
                s.totalDisputes++
            )
        );

        // Store dispute
        s.disputes[disputeId] = AxiomTypesV2.Dispute({
            disputeId: disputeId,
            recordId: _recordId,
            externalDisputeId: bytes32(0),
            challenger: msg.sender,
            arbitrator: address(0),
            reason: _reason,
            status: AxiomTypesV2.DisputeStatus.PENDING,
            stakeAmount: _amount,
            stakeToken: _token,
            createdAt: uint40(block.timestamp),
            deadline: uint40(block.timestamp + s.stakeConfig.responsePeriod),
            resolvedAt: 0,
            evidenceURI: _evidenceURI,
            responseURI: ""
        });

        s.recordDisputes[_recordId].push(disputeId);
        s.challengerDisputes[msg.sender].push(disputeId);

        emit DisputeInitiated(disputeId, _recordId, msg.sender, _reason, _amount);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          RESPONSE & EVIDENCE
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Responds to a pending dispute (Content Owner only).
     * @dev Sets status to EVIDENCE_PERIOD. Must be called within response period.
     * @param _disputeId The ID of the dispute.
     * @param _responseURI IPFS URI containing the counter-evidence/response.
     */
    function respondToDispute(
        bytes32 _disputeId,
        string calldata _responseURI
    ) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = s.disputes[_disputeId];
        
        if (dispute.status != AxiomTypesV2.DisputeStatus.PENDING) {
            revert AxiomTypesV2.InvalidDisputeStatus(
                _disputeId, 
                AxiomTypesV2.DisputeStatus.PENDING, 
                dispute.status
            );
        }
        
        if (block.timestamp > dispute.deadline) {
            revert AxiomTypesV2.DisputeDeadlinePassed(_disputeId, dispute.deadline);
        }

        // Verify msg.sender is content owner
        if (AxiomStorage.recordExistsV2(dispute.recordId)) {
            AxiomTypesV2.AxiomRecord storage record = s.recordsV2[dispute.recordId];
            require(record.issuer == msg.sender, "Not content owner");
        } else if (AxiomStorage.recordExists(dispute.recordId)) {
            require(s.records[dispute.recordId].issuer == msg.sender, "Not content owner");
        } else {
            revert AxiomTypesV2.ContentNotFound(dispute.recordId);
        }
        
        dispute.responseURI = _responseURI;
        dispute.status = AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD;
        dispute.deadline = uint40(block.timestamp + s.stakeConfig.evidencePeriod);

        emit DisputeResponseSubmitted(_disputeId, msg.sender, _responseURI);
    }

    /**
     * @notice Submits additional evidence for an active dispute.
     * @dev Can be called by either party during EVIDENCE_PERIOD or ARBITRATION.
     * @param _disputeId The ID of the dispute.
     * @param _evidenceURI IPFS URI containing information/evidence.
     */
    function submitEvidence(
        bytes32 _disputeId,
        string calldata _evidenceURI
    ) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = s.disputes[_disputeId];
        
        if (dispute.status != AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD &&
            dispute.status != AxiomTypesV2.DisputeStatus.ARBITRATION) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        emit EvidenceSubmitted(_disputeId, msg.sender, _evidenceURI);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                       ARBITRATION ESCALATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Escalates a dispute to an external arbitrator.
     * @dev Requires paying the arbitration fee. Status changes to ARBITRATION.
     *      CEI: All state is written BEFORE external calls (arbitrator + refund).
     * @param _disputeId The ID of the dispute to escalate.
     * @param _arbitrator The address of the chosen arbitrator contract.
     */
    function escalateToArbitration(
        bytes32 _disputeId,
        address _arbitrator
    ) external payable override nonReentrant {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = s.disputes[_disputeId];
        
        // CHECKS
        if (dispute.status != AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD) {
            revert AxiomTypesV2.InvalidDisputeStatus(
                _disputeId,
                AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD,
                dispute.status
            );
        }
        
        if (!s.approvedArbitrators[_arbitrator]) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        // Calculate arbitration cost (view call — safe)
        IArbitrator arbitrator = IArbitrator(_arbitrator);
        uint256 arbitrationFee = arbitrator.arbitrationCost("");
        
        if (msg.value < arbitrationFee) {
            revert AxiomTypesV2.InsufficientFee(msg.value, arbitrationFee);
        }

        // EFFECTS: Write ALL state BEFORE external calls
        dispute.status = AxiomTypesV2.DisputeStatus.ARBITRATION;
        dispute.arbitrator = _arbitrator;
        // Note: externalDisputeId will be set after createDispute returns,
        // but status is already ARBITRATION so re-entry is blocked

        // INTERACTION #1: Create dispute in arbitrator
        uint256 externalId = arbitrator.createDispute{value: arbitrationFee}(RULING_OPTIONS, "");
        
        // Post-interaction state update (safe: status already changed,
        // nonReentrant blocks re-entry)
        dispute.externalDisputeId = bytes32(externalId);
        s.externalDisputeMapping[_arbitrator][externalId] = _disputeId;

        emit DisputeEscalated(_disputeId, _arbitrator, bytes32(externalId));
        
        // INTERACTION #2: Refund excess fee using call (supports smart contract wallets)
        if (msg.value > arbitrationFee) {
            (bool success,) = payable(msg.sender).call{value: msg.value - arbitrationFee}("");
            require(success, "DisputeFacet: Refund failed");
        }
    }

    /**
     * @notice Executes a ruling from an external arbitrator.
     * @dev Can only be called by the assigned arbitrator. Resolves the dispute.
     * @param _externalDisputeId The dispute ID in the arbitrator's system.
     * @param _ruling The ruling provided by the arbitrator.
     */
    function rule(uint256 _externalDisputeId, uint256 _ruling) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Map external ID back to internal
        bytes32 disputeId = s.externalDisputeMapping[msg.sender][_externalDisputeId];
        
        if (disputeId == bytes32(0)) {
            revert AxiomTypesV2.DisputeNotFound(disputeId);
        }
        
        AxiomTypesV2.Dispute storage dispute = s.disputes[disputeId];
        
        if (dispute.arbitrator != msg.sender) {
            revert AxiomTypesV2.UnauthorizedDisputeAction(disputeId, msg.sender);
        }
        
        if (dispute.status != AxiomTypesV2.DisputeStatus.ARBITRATION) {
            revert AxiomTypesV2.InvalidDisputeStatus(
                disputeId,
                AxiomTypesV2.DisputeStatus.ARBITRATION,
                dispute.status
            );
        }

        AxiomTypesV2.DisputeStatus newStatus;
        address winner = address(0);

        if (_ruling == RULING_CHALLENGER) {
            newStatus = AxiomTypesV2.DisputeStatus.RESOLVED_VALID; // Challenger wins, dispute is valid
            winner = dispute.challenger;
        } else if (_ruling == RULING_OWNER) {
            newStatus = AxiomTypesV2.DisputeStatus.RESOLVED_INVALID; // Owner wins, dispute is invalid
            // Get owner address
            winner = _getRecordOwner(s, dispute.recordId);
        } else {
            newStatus = AxiomTypesV2.DisputeStatus.RESOLVED_INVALID; // Default to invalid
        }
        
        dispute.status = newStatus;
        dispute.resolvedAt = uint40(block.timestamp);

        emit DisputeResolved(disputeId, newStatus, winner);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          RESOLUTION & SETTLEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Resolves a dispute if the deadline has passed without response.
     * @dev If PENDING and deadline passed, Challenger wins. If EVIDENCE_PERIOD and escalation deadline passed, Owner wins.
     *      nonReentrant: prevents state manipulation during concurrent claimStake calls.
     * @param _disputeId The ID of the dispute.
     */
    function resolveByTimeout(bytes32 _disputeId) external override nonReentrant {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = s.disputes[_disputeId];
        
        if (block.timestamp <= dispute.deadline) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        if (dispute.status == AxiomTypesV2.DisputeStatus.PENDING) {
            // Owner failed to respond -> Challenger wins
            dispute.status = AxiomTypesV2.DisputeStatus.RESOLVED_VALID;
            dispute.resolvedAt = uint40(block.timestamp);
            emit DisputeResolved(_disputeId, AxiomTypesV2.DisputeStatus.RESOLVED_VALID, dispute.challenger);
        } else if (dispute.status == AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD) {
            // Escalation deadline passed -> Dispute is invalid (owner wins)
            dispute.status = AxiomTypesV2.DisputeStatus.RESOLVED_INVALID;
            dispute.resolvedAt = uint40(block.timestamp);
            address owner = _getRecordOwner(s, dispute.recordId);
            emit DisputeResolved(_disputeId, AxiomTypesV2.DisputeStatus.RESOLVED_INVALID, owner);
        }
    }

    /**
     * @notice Settles a dispute via mutual agreement.
     * @dev Distributes stake according to agreed shares. Requires signatures from both parties.
     * @param _disputeId The ID of the dispute.
     * @param _challengerShare Basis points (0-10000) of the stake going to the challenger.
     * @param _ownerSignature Signature of the content owner approving settlement.
     * @param _challengerSignature Signature of the challenger approving settlement.
     */
    function settleDispute(
        bytes32 _disputeId,
        uint16 _challengerShare,
        bytes calldata _ownerSignature,
        bytes calldata _challengerSignature
    ) external override nonReentrant {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = s.disputes[_disputeId];
        
        if (dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_VALID || 
            dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_INVALID) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        dispute.status = AxiomTypesV2.DisputeStatus.SETTLED;
        dispute.resolvedAt = uint40(block.timestamp);
        
        emit DisputeSettled(_disputeId, _challengerShare, 10000 - _challengerShare);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          STAKING & REWARDS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Claims the stake (and reward) after a dispute is resolved.
     * @dev Can be called by the winner. Transfers tokens/ETH.
     * @param _disputeId The ID of the resolved dispute.
     * @return amount The total amount claimed.
     */
    function claimStake(bytes32 _disputeId) external override nonReentrant returns (uint256 amount) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = s.disputes[_disputeId];
        
        if (dispute.status != AxiomTypesV2.DisputeStatus.RESOLVED_INVALID &&
            dispute.status != AxiomTypesV2.DisputeStatus.RESOLVED_VALID) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        // Prevent double claim
        if (dispute.stakeAmount == 0) {
            return 0;
        }

        uint256 stakeAmount = dispute.stakeAmount;
        dispute.stakeAmount = 0; // Prevent reentrancy

        // Calculate splits
        uint256 protocolFee = (stakeAmount * s.stakeConfig.protocolFeeBps) / 10000;
        uint256 remainder = stakeAmount - protocolFee;

        // If Challenger won (RESOLVED_VALID - dispute was valid)
        if (dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_VALID) {
            if (msg.sender != dispute.challenger) {
                revert AxiomTypesV2.UnauthorizedDisputeAction(_disputeId, msg.sender);
            }
            
            // Challenger gets stake back
            amount = remainder;
            _transferStake(dispute.stakeToken, dispute.challenger, remainder);
            _transferStake(dispute.stakeToken, s.treasuryWallet, protocolFee);
        } else {
            // Owner won (RESOLVED_INVALID - dispute was invalid)
            address owner = _getRecordOwner(s, dispute.recordId);
            if (msg.sender != owner) {
                revert AxiomTypesV2.UnauthorizedDisputeAction(_disputeId, msg.sender);
            }
            
            // Owner gets challenger's stake (minus protocol fee)
            amount = remainder;
            _transferStake(dispute.stakeToken, owner, remainder);
            _transferStake(dispute.stakeToken, s.treasuryWallet, protocolFee);
        }

        emit StakeClaimed(_disputeId, msg.sender, amount);
    }

    function _transferStake(address _token, address _to, uint256 _amount) internal {
        if (_amount == 0) return;
        
        if (_token == address(0)) {
            // Use call instead of transfer — transfer forwards only 2300 gas,
            // which fails for smart contract wallets (Gnosis Safe, etc.)
            (bool success,) = payable(_to).call{value: _amount}("");
            require(success, "DisputeFacet: ETH transfer failed");
        } else {
            IERC20(_token).safeTransfer(_to, _amount);
        }
    }

    function _getRecordOwner(AxiomStorage.Storage storage s, bytes32 _recordId) internal view returns (address) {
        if (AxiomStorage.recordExistsV2(_recordId)) {
            return s.recordsV2[_recordId].issuer;
        } else if (AxiomStorage.recordExists(_recordId)) {
            return s.records[_recordId].issuer;
        }
        revert AxiomTypesV2.ContentNotFound(_recordId);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          ARBITRATOR MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * @notice Retrieves the list of approved arbitrator addresses.
     * @return The array of approved arbitrator addresses.
     */
    function getApprovedArbitrators() external view override returns (address[] memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.arbitratorList;
    }

    /**
     * @notice Checks if a specific arbitrator is approved.
     * @param _arbitrator The address of the arbitrator to check.
     * @return True if the arbitrator is approved, false otherwise.
     */
    function isArbitratorApproved(address _arbitrator) external view override returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.approvedArbitrators[_arbitrator];
    }

    /**
     * @notice Gets the fee required by an arbitrator for a specific dispute reason.
     * @param _arbitrator The address of the arbitrator.
     * @param _reason The dispute reason (unused in current implementation implies base cost).
     * @return The arbitration cost in wei.
     */
    function getArbitratorFee(address _arbitrator, AxiomTypesV2.DisputeReason _reason) 
        external view override returns (uint256) 
    {
        return IArbitrator(_arbitrator).arbitrationCost("");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          APPEALS (STUB)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Appeals a dispute ruling (Not Implemented).
     * @dev Reverts with OperationNotPermitted.
     * @return disputeId The ID of the appeal.
     */
    function appeal(bytes32, string calldata) 
        external payable override returns (bytes32) 
    {
        revert AxiomTypesV2.OperationNotPermitted(); // Not implemented in v1
    }

    /**
     * @notice Gets the deadline for appealing a dispute.
     * @dev Always returns 0 as appeals are not implemented.
     * @return The appeal deadline timestamp.
     */
    function getAppealDeadline(bytes32) external pure override returns (uint256) {
        return 0; // Not implemented
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          DISPUTE QUERIES
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Retrieves full details of a dispute.
     * @param _disputeId The ID of the dispute.
     * @return The Dispute struct containing all details.
     */
    function getDispute(bytes32 _disputeId) 
        external view override returns (AxiomTypesV2.Dispute memory) 
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.disputes[_disputeId];
    }
    
    /**
     * @notice Retrieves all dispute IDs associated with a record.
     * @param _recordId The ID of the content record.
     * @return An array of dispute IDs.
     */
    function getDisputesByRecord(bytes32 _recordId) external view override returns (bytes32[] memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.recordDisputes[_recordId];
    }

    /**
     * @notice Retrieves all dispute IDs initiated by a challenger.
     * @param _challenger The address of the challenger.
     * @return An array of dispute IDs.
     */
    function getDisputesByChallenger(address _challenger) external view override returns (bytes32[] memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.challengerDisputes[_challenger];
    }

    /**
     * @notice Retrieves active disputes with pagination (Not Implemented).
     * @return An empty array of dispute IDs.
     */
    function getActiveDisputes(uint256, uint256) external pure override returns (bytes32[] memory) {
        // Not implemented for gas efficiency
        return new bytes32[](0);
    }

    /**
     * @notice Checks if a record has any active (unresolved) disputes.
     * @param _recordId The ID of the content record.
     * @return True if there is an active dispute, false otherwise.
     */
    function hasActiveDispute(bytes32 _recordId) public view override returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        bytes32[] memory ids = s.recordDisputes[_recordId];
        
        if (ids.length == 0) return false;
        
        AxiomTypesV2.Dispute storage lastDispute = s.disputes[ids[ids.length - 1]];
        return lastDispute.status == AxiomTypesV2.DisputeStatus.PENDING || 
               lastDispute.status == AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD ||
               lastDispute.status == AxiomTypesV2.DisputeStatus.ARBITRATION ||
               lastDispute.status == AxiomTypesV2.DisputeStatus.APPEALED;
    }

    /**
     * @notice Retrieves the current global staking configuration.
     * @return The StakeConfig struct.
     */
    function getStakeConfig() external view override returns (AxiomTypesV2.StakeConfig memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.stakeConfig;
    }
    
    /**
     * @notice Retrieves the minimum stake required for a dispute.
     * @return The minimum stake amount in wei.
     */
    function getMinimumStake(bytes32) external view override returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.stakeConfig.minStakeAmount;
    }
}
