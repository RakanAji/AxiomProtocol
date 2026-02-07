// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";

/**
 * @title IAxiomDispute
 * @author Axiom Protocol Team
 * @notice Interface for decentralized content dispute resolution
 * @dev Replaces centralized OPERATOR_ROLE with community-driven arbitration
 *      
 *      This interface enables:
 *      - Anyone to challenge content with staked tokens
 *      - Content owners to respond with evidence
 *      - Escalation to external arbitration (Kleros, Aragon Court, UMA)
 *      - Economic incentives to prevent spam disputes
 *
 *      Dispute Flow:
 *      1. Challenger stakes tokens and initiates dispute
 *      2. Content owner has response period to submit evidence
 *      3. If unresolved, dispute escalates to external arbitrator
 *      4. Arbitrator ruling is enforced on-chain
 *      5. Stake is distributed based on outcome
 *
 *      Integration Protocols:
 *      - Kleros: https://kleros.io
 *      - Aragon Court: https://aragon.org/court
 *      - UMA Optimistic Oracle: https://umaproject.org
 */
interface IAxiomDispute {
    // ═══════════════════════════════════════════════════════════════════════════
    //                          DISPUTE INITIATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Initiate a dispute against registered content
     * @dev Challenger must stake tokens to prevent spam
     *      Stake is returned (plus reward) if dispute is valid
     *      Stake is forfeited if dispute is invalid
     *
     *      Requirements:
     *      - Content must exist and be ACTIVE
     *      - Stake must meet minimum requirement
     *      - No active dispute for same content by same challenger
     *      - Caller cannot dispute their own content
     *
     *      Emits {DisputeInitiated} event
     *
     * @param _recordId Content record ID being disputed
     * @param _reason Category of dispute (COPYRIGHT, FALSE_ATTRIBUTION, etc.)
     * @param _evidenceURI IPFS link to evidence supporting the dispute
     * @return disputeId Unique identifier for the dispute
     */
    function initiateDispute(
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI
    ) external payable returns (bytes32 disputeId);

    /**
     * @notice Initiate dispute with ERC-20 token stake
     * @dev Alternative to ETH staking for protocols with native tokens
     *
     * @param _recordId Content record ID
     * @param _reason Dispute reason
     * @param _evidenceURI Evidence URI
     * @param _stakeToken ERC-20 token for stake
     * @param _stakeAmount Amount to stake
     * @return disputeId Dispute identifier
     */
    function initiateDisputeWithToken(
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI,
        address _stakeToken,
        uint256 _stakeAmount
    ) external returns (bytes32 disputeId);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          RESPONSE & EVIDENCE
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Submit response to a dispute (content owner only)
     * @dev Content owner can provide counter-evidence
     *      Must be submitted within response period
     *
     *      Requirements:
     *      - Caller must be the content issuer
     *      - Dispute must be in PENDING status
     *      - Response period must not have expired
     *
     *      Emits {DisputeResponseSubmitted} event
     *      Status changes to EVIDENCE_PERIOD
     *
     * @param _disputeId Dispute ID to respond to
     * @param _responseURI IPFS link to counter-evidence
     */
    function respondToDispute(
        bytes32 _disputeId,
        string calldata _responseURI
    ) external;

    /**
     * @notice Submit additional evidence during evidence period
     * @dev Both parties can submit additional evidence until deadline
     *
     *      Requirements:
     *      - Dispute must be in EVIDENCE_PERIOD status
     *      - Evidence deadline must not have passed
     *      - Caller must be challenger or content owner
     *
     * @param _disputeId Dispute ID
     * @param _evidenceURI IPFS link to additional evidence
     */
    function submitEvidence(
        bytes32 _disputeId,
        string calldata _evidenceURI
    ) external;

    // ═══════════════════════════════════════════════════════════════════════════
    //                       ARBITRATION ESCALATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Escalate dispute to external arbitration protocol
     * @dev Transfers dispute data to selected arbitrator (Kleros, Aragon, etc.)
     *      Additional fees may be required by the arbitrator
     *
     *      Requirements:
     *      - Dispute must be in EVIDENCE_PERIOD status
     *      - Evidence period must have ended OR both parties agree
     *      - Arbitrator must be a registered/approved protocol
     *
     *      Emits {DisputeEscalated} event
     *      Status changes to ARBITRATION
     *
     * @param _disputeId Dispute ID to escalate
     * @param _arbitrator Address of the arbitration protocol
     */
    function escalateToArbitration(
        bytes32 _disputeId,
        address _arbitrator
    ) external payable;

    /**
     * @notice Receive ruling from external arbitrator
     * @dev Callback function called by arbitrator adapters
     *      Implements IArbitrable interface for Kleros compatibility
     *
     *      Requirements:
     *      - Caller must be the registered arbitrator adapter
     *      - Dispute must be in ARBITRATION status
     *
     *      Emits {DisputeResolved} event
     *
     * @param _externalDisputeId External arbitrator's dispute ID
     * @param _ruling The ruling: 0 = refused to rule, 1 = challenger wins, 2 = owner wins
     */
    function rule(uint256 _externalDisputeId, uint256 _ruling) external;

    // ═══════════════════════════════════════════════════════════════════════════
    //                          RESOLUTION & SETTLEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Resolve dispute directly (if no response within deadline)
     * @dev Auto-resolves in favor of challenger if owner doesn't respond
     *      Auto-resolves in favor of owner if challenger abandons
     *
     *      Requirements:
     *      - Dispute must be in PENDING or EVIDENCE_PERIOD status
     *      - Relevant deadline must have passed
     *
     *      Emits {DisputeResolved} event
     *
     * @param _disputeId Dispute ID to resolve
     */
    function resolveByTimeout(bytes32 _disputeId) external;

    /**
     * @notice Mutual settlement between parties
     * @dev Both parties agree to split stakes and resolve
     *
     *      Requirements:
     *      - Dispute must not be RESOLVED/SETTLED already
     *      - Both parties must have signed settlement terms
     *
     *      Emits {DisputeSettled} event
     *
     * @param _disputeId Dispute ID
     * @param _challengerShare Percentage of stake to challenger (0-10000 bps)
     * @param _ownerSignature Owner's signature approving settlement
     * @param _challengerSignature Challenger's signature approving settlement
     */
    function settleDispute(
        bytes32 _disputeId,
        uint16 _challengerShare,
        bytes calldata _ownerSignature,
        bytes calldata _challengerSignature
    ) external;

    // ═══════════════════════════════════════════════════════════════════════════
    //                          STAKING & REWARDS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Claim stake after dispute resolution
     * @dev Winner claims their stake plus reward from loser's stake
     *
     *      Reward Distribution:
     *      - Winner: Original stake + (loser stake * reward percentage)
     *      - Protocol: (loser stake * protocol fee percentage)
     *      - Remainder burned or sent to treasury
     *
     *      Requirements:
     *      - Dispute must be RESOLVED_VALID, RESOLVED_INVALID, or SETTLED
     *      - Caller must be the winner or entitled to claim
     *      - Stake must not have been claimed already
     *
     *      Emits {StakeClaimed} event
     *
     * @param _disputeId Dispute ID to claim stake from
     * @return amount Total amount claimed
     */
    function claimStake(bytes32 _disputeId) external returns (uint256 amount);

    /**
     * @notice Get current stake configuration
     * @return config StakeConfig struct with all parameters
     */
    function getStakeConfig() external view returns (AxiomTypesV2.StakeConfig memory config);

    /**
     * @notice Get minimum stake required for a dispute
     * @dev May vary based on content type or dispute reason
     *
     * @param _recordId Content being disputed
     * @return minStake Minimum required stake
     */
    function getMinimumStake(bytes32 _recordId) external view returns (uint256 minStake);

    // ═══════════════════════════════════════════════════════════════════════════
    //                              APPEALS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Appeal a dispute resolution
     * @dev Requires additional stake; sends to higher court/new arbitrator panel
     *
     *      Requirements:
     *      - Dispute must be RESOLVED (not SETTLED)
     *      - Appeal period must not have expired
     *      - Appellant must stake appeal amount
     *      - Only one appeal allowed per party
     *
     *      Emits {DisputeAppealed} event
     *      Status changes to APPEALED
     *
     * @param _disputeId Dispute ID to appeal
     * @param _appealReason IPFS link to appeal justification
     * @return appealId Unique appeal identifier
     */
    function appeal(
        bytes32 _disputeId,
        string calldata _appealReason
    ) external payable returns (bytes32 appealId);

    /**
     * @notice Get remaining time to appeal
     * @param _disputeId Dispute ID
     * @return remainingSeconds Seconds until appeal deadline (0 if expired)
     */
    function getAppealDeadline(bytes32 _disputeId) 
        external view returns (uint256 remainingSeconds);

    // ═══════════════════════════════════════════════════════════════════════════
    //                          DISPUTE QUERIES
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get full dispute information
     * @param _disputeId Dispute ID to query
     * @return dispute Full Dispute struct
     */
    function getDispute(bytes32 _disputeId) 
        external view returns (AxiomTypesV2.Dispute memory dispute);

    /**
     * @notice Get all disputes for a content record
     * @param _recordId Content record ID
     * @return disputeIds Array of dispute IDs
     */
    function getDisputesByRecord(bytes32 _recordId) 
        external view returns (bytes32[] memory disputeIds);

    /**
     * @notice Get all disputes initiated by an address
     * @param _challenger Challenger address
     * @return disputeIds Array of dispute IDs
     */
    function getDisputesByChallenger(address _challenger) 
        external view returns (bytes32[] memory disputeIds);

    /**
     * @notice Get active disputes (not yet resolved)
     * @param _offset Pagination offset
     * @param _limit Maximum results to return
     * @return disputeIds Array of active dispute IDs
     */
    function getActiveDisputes(uint256 _offset, uint256 _limit) 
        external view returns (bytes32[] memory disputeIds);

    /**
     * @notice Check if content has any active disputes
     * @param _recordId Content record ID
     * @return hasActive Whether content has active disputes
     */
    function hasActiveDispute(bytes32 _recordId) external view returns (bool hasActive);

    // ═══════════════════════════════════════════════════════════════════════════
    //                       ARBITRATOR MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get list of approved arbitration protocols
     * @return arbitrators Array of arbitrator addresses
     */
    function getApprovedArbitrators() external view returns (address[] memory arbitrators);

    /**
     * @notice Check if arbitrator is approved
     * @param _arbitrator Arbitrator address to check
     * @return isApproved Whether arbitrator is approved
     */
    function isArbitratorApproved(address _arbitrator) external view returns (bool isApproved);

    /**
     * @notice Get arbitrator fee for a dispute
     * @param _arbitrator Arbitrator address
     * @param _reason Dispute reason (affects subcourt selection)
     * @return fee Required fee in ETH
     */
    function getArbitratorFee(address _arbitrator, AxiomTypesV2.DisputeReason _reason) 
        external view returns (uint256 fee);

    // ═══════════════════════════════════════════════════════════════════════════
    //                              EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Emitted when dispute is initiated
     * @param disputeId Unique dispute identifier
     * @param recordId Content being disputed
     * @param challenger Address initiating dispute
     * @param reason Category of dispute
     * @param stakeAmount Amount staked
     */
    event DisputeInitiated(
        bytes32 indexed disputeId,
        bytes32 indexed recordId,
        address indexed challenger,
        AxiomTypesV2.DisputeReason reason,
        uint256 stakeAmount
    );

    /**
     * @notice Emitted when content owner responds to dispute
     * @param disputeId Dispute being responded to
     * @param owner Content owner address
     * @param responseURI IPFS link to response
     */
    event DisputeResponseSubmitted(
        bytes32 indexed disputeId,
        address indexed owner,
        string responseURI
    );

    /**
     * @notice Emitted when additional evidence is submitted
     * @param disputeId Related dispute
     * @param submitter Address submitting evidence
     * @param evidenceURI IPFS link to evidence
     */
    event EvidenceSubmitted(
        bytes32 indexed disputeId,
        address indexed submitter,
        string evidenceURI
    );

    /**
     * @notice Emitted when dispute is escalated to external arbitrator
     * @param disputeId Internal dispute ID
     * @param arbitrator Address of arbitration protocol
     * @param externalDisputeId ID assigned by external arbitrator
     */
    event DisputeEscalated(
        bytes32 indexed disputeId,
        address indexed arbitrator,
        bytes32 externalDisputeId
    );

    /**
     * @notice Emitted when dispute is resolved
     * @param disputeId Dispute that was resolved
     * @param outcome Final status (RESOLVED_VALID or RESOLVED_INVALID)
     * @param winner Address of winning party
     */
    event DisputeResolved(
        bytes32 indexed disputeId,
        AxiomTypesV2.DisputeStatus outcome,
        address indexed winner
    );

    /**
     * @notice Emitted when dispute is settled by mutual agreement
     * @param disputeId Dispute that was settled
     * @param challengerShare Percentage to challenger
     * @param ownerShare Percentage to owner
     */
    event DisputeSettled(
        bytes32 indexed disputeId,
        uint16 challengerShare,
        uint16 ownerShare
    );

    /**
     * @notice Emitted when stake is claimed after resolution
     * @param disputeId Related dispute
     * @param claimant Address claiming stake
     * @param amount Amount claimed
     */
    event StakeClaimed(
        bytes32 indexed disputeId,
        address indexed claimant,
        uint256 amount
    );

    /**
     * @notice Emitted when dispute is appealed
     * @param disputeId Original dispute ID
     * @param appealId New appeal ID
     * @param appellant Address filing appeal
     * @param additionalStake Extra stake for appeal
     */
    event DisputeAppealed(
        bytes32 indexed disputeId,
        bytes32 indexed appealId,
        address indexed appellant,
        uint256 additionalStake
    );
}
