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

    /// @inheritdoc IAxiomDispute
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

    /// @inheritdoc IAxiomDispute
    function initiateDisputeWithToken(
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI,
        address _stakeToken,
        uint256 _stakeAmount
    ) external override nonReentrant returns (bytes32 disputeId) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        // Verify configured token
        if (_stakeToken != s.stakeConfig.stakeToken) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        // Transfer tokens
        IERC20(_stakeToken).safeTransferFrom(msg.sender, address(this), _stakeAmount);

        return _initiateDispute(
            s, 
            _recordId, 
            _reason, 
            _evidenceURI, 
            _stakeToken, 
            _stakeAmount
        );
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

    /// @inheritdoc IAxiomDispute
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

    /// @inheritdoc IAxiomDispute
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

    /// @inheritdoc IAxiomDispute
    function escalateToArbitration(
        bytes32 _disputeId,
        address _arbitrator
    ) external payable override nonReentrant {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = s.disputes[_disputeId];
        
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

        // Calculate arbitration cost
        IArbitrator arbitrator = IArbitrator(_arbitrator);
        uint256 arbitrationFee = arbitrator.arbitrationCost("");
        
        if (msg.value < arbitrationFee) {
            revert AxiomTypesV2.InsufficientFee(msg.value, arbitrationFee);
        }

        // Create dispute in arbitrator
        uint256 externalId = arbitrator.createDispute{value: arbitrationFee}(RULING_OPTIONS, "");
        
        dispute.status = AxiomTypesV2.DisputeStatus.ARBITRATION;
        dispute.arbitrator = _arbitrator;
        dispute.externalDisputeId = bytes32(externalId);
        
        s.externalDisputeMapping[_arbitrator][externalId] = _disputeId;

        emit DisputeEscalated(_disputeId, _arbitrator, bytes32(externalId));
        
        // Refund excess fee
        if (msg.value > arbitrationFee) {
            payable(msg.sender).transfer(msg.value - arbitrationFee);
        }
    }

    /// @inheritdoc IAxiomDispute
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

    /// @inheritdoc IAxiomDispute
    function resolveByTimeout(bytes32 _disputeId) external override {
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

    /// @inheritdoc IAxiomDispute
    function settleDispute(
        bytes32 _disputeId,
        uint16 _challengerShare,
        bytes calldata /*_ownerSignature*/,
        bytes calldata /*_challengerSignature*/
    ) external override {
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

    /// @inheritdoc IAxiomDispute
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
            payable(_to).transfer(_amount);
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
    
    /// @inheritdoc IAxiomDispute
    function getApprovedArbitrators() external view override returns (address[] memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.arbitratorList;
    }

    /// @inheritdoc IAxiomDispute
    function isArbitratorApproved(address _arbitrator) external view override returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.approvedArbitrators[_arbitrator];
    }

    /// @inheritdoc IAxiomDispute
    function getArbitratorFee(address _arbitrator, AxiomTypesV2.DisputeReason) 
        external view override returns (uint256) 
    {
        return IArbitrator(_arbitrator).arbitrationCost("");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          APPEALS (STUB)
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomDispute
    function appeal(bytes32, string calldata) 
        external payable override returns (bytes32) 
    {
        revert AxiomTypesV2.OperationNotPermitted(); // Not implemented in v1
    }

    /// @inheritdoc IAxiomDispute
    function getAppealDeadline(bytes32) external pure override returns (uint256) {
        return 0; // Not implemented
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          DISPUTE QUERIES
    // ═══════════════════════════════════════════════════════════════════════════

    /// @inheritdoc IAxiomDispute
    function getDispute(bytes32 _disputeId) 
        external view override returns (AxiomTypesV2.Dispute memory) 
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.disputes[_disputeId];
    }
    
    /// @inheritdoc IAxiomDispute
    function getDisputesByRecord(bytes32 _recordId) external view override returns (bytes32[] memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.recordDisputes[_recordId];
    }

    /// @inheritdoc IAxiomDispute
    function getDisputesByChallenger(address _challenger) external view override returns (bytes32[] memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.challengerDisputes[_challenger];
    }

    /// @inheritdoc IAxiomDispute
    function getActiveDisputes(uint256, uint256) external pure override returns (bytes32[] memory) {
        // Not implemented for gas efficiency
        return new bytes32[](0);
    }

    /// @inheritdoc IAxiomDispute
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

    /// @inheritdoc IAxiomDispute
    function getStakeConfig() external view override returns (AxiomTypesV2.StakeConfig memory) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.stakeConfig;
    }
    
    /// @inheritdoc IAxiomDispute
    function getMinimumStake(bytes32) external view override returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.stakeConfig.minStakeAmount;
    }
}
