// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {AxiomTypes} from "../libraries/AxiomTypes.sol";
import {AxiomTypesV2} from "../libraries/AxiomTypesV2.sol";
import {IAxiomDispute} from "../interfaces/IAxiomDispute.sol";
import {IArbitrator} from "../interfaces/IArbitrator.sol";

interface IDisputeRouterAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

/**
 * @title AxiomDisputeFacet
 * @notice Stake-backed content disputes executed through AxiomRouter delegatecall.
 */
contract AxiomDisputeFacet is IAxiomDispute {
    using SafeERC20 for IERC20;
    using MessageHashUtils for bytes32;

    uint256 private constant RULING_OPTIONS = 2;
    uint256 private constant RULING_CHALLENGER = 1;
    uint256 private constant RULING_OWNER = 2;
    uint256 private constant BPS_DENOMINATOR = 10_000;
    bytes32 private constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 private constant SETTLEMENT_TYPEHASH =
        keccak256("AxiomDisputeSettlement(address router,uint256 chainId,bytes32 disputeId,uint16 challengerShare)");

    modifier nonReentrant() {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        require(s.reentrancyStatus != 2, "ReentrancyGuard: reentrant call");
        s.reentrancyStatus = 2;
        _;
        s.reentrancyStatus = 1;
    }

    modifier whenNotPaused() {
        require(!AxiomStorage.getStorage().paused, "Protocol is paused");
        _;
    }

    modifier onlyAdmin() {
        require(
            IDisputeRouterAccessControl(address(this)).hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "DisputeFacet: missing admin role"
        );
        _;
    }

    modifier notBanned() {
        if (AxiomStorage.getStorage().bannedAddresses[msg.sender]) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        _;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                              ADMIN CONFIG
    // ═══════════════════════════════════════════════════════════════════════════

    function configureStakeConfig(AxiomTypesV2.StakeConfig calldata _config) external override onlyAdmin {
        _validateStakeConfig(_config);
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.stakeConfig = _config;
        s.disputeSystemInitialized = true;
        emit StakeConfigUpdated(_config.stakeToken, _config.minStakeAmount);
    }

    function setArbitrator(address _arbitrator, bool _approved) external override onlyAdmin {
        if (_arbitrator == address(0) || (_approved && _arbitrator.code.length == 0)) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        if (_approved && !s.approvedArbitrators[_arbitrator]) {
            bool listed;
            for (uint256 i = 0; i < s.arbitratorList.length; i++) {
                if (s.arbitratorList[i] == _arbitrator) {
                    listed = true;
                    break;
                }
            }
            if (!listed) s.arbitratorList.push(_arbitrator);
        }
        s.approvedArbitrators[_arbitrator] = _approved;
        emit ArbitratorApprovalUpdated(_arbitrator, _approved);
    }

    function _validateStakeConfig(AxiomTypesV2.StakeConfig calldata _config) internal view {
        if (
            _config.minStakeAmount == 0 || _config.responsePeriod == 0 || _config.evidencePeriod == 0
                || _config.appealPeriod == 0 || _config.protocolFeeBps > BPS_DENOMINATOR || _config.rewardBps != 0
                || _config.slashBps != 0 || (_config.stakeToken != address(0) && _config.stakeToken.code.length == 0)
        ) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                            DISPUTE LIFECYCLE
    // ═══════════════════════════════════════════════════════════════════════════

    function initiateDispute(bytes32 _recordId, AxiomTypesV2.DisputeReason _reason, string calldata _evidenceURI)
        external
        payable
        override
        nonReentrant
        whenNotPaused
        notBanned
        returns (bytes32 disputeId)
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        _requireConfigured(s);
        if (s.stakeConfig.stakeToken != address(0)) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        return _initiateDispute(s, _recordId, _reason, _evidenceURI, address(0), msg.value);
    }

    function initiateDisputeWithToken(
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI,
        address _stakeToken,
        uint256 _stakeAmount
    ) external override nonReentrant whenNotPaused notBanned returns (bytes32 disputeId) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        _requireConfigured(s);
        if (_stakeToken == address(0) || _stakeToken != s.stakeConfig.stakeToken) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        uint256 balanceBefore = IERC20(_stakeToken).balanceOf(address(this));
        disputeId = _initiateDispute(s, _recordId, _reason, _evidenceURI, _stakeToken, _stakeAmount);
        IERC20(_stakeToken).safeTransferFrom(msg.sender, address(this), _stakeAmount);
        if (IERC20(_stakeToken).balanceOf(address(this)) - balanceBefore != _stakeAmount) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
    }

    function _initiateDispute(
        AxiomStorage.Storage storage s,
        bytes32 _recordId,
        AxiomTypesV2.DisputeReason _reason,
        string calldata _evidenceURI,
        address _token,
        uint256 _amount
    ) internal returns (bytes32 disputeId) {
        address owner = _requireActiveRecord(s, _recordId);
        if (owner == msg.sender || _amount < s.stakeConfig.minStakeAmount || hasActiveDispute(_recordId)) {
            if (_amount < s.stakeConfig.minStakeAmount) {
                revert AxiomTypesV2.InsufficientStake(_amount, s.stakeConfig.minStakeAmount);
            }
            revert AxiomTypesV2.OperationNotPermitted();
        }

        uint256 nonce = s.totalDisputes++;
        disputeId = keccak256(abi.encode(address(this), block.chainid, _recordId, msg.sender, nonce));
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
            deadline: _deadline(s.stakeConfig.responsePeriod),
            resolvedAt: 0,
            evidenceURI: _evidenceURI,
            responseURI: ""
        });
        s.recordDisputes[_recordId].push(disputeId);
        s.challengerDisputes[msg.sender].push(disputeId);
        s.allDisputeIds.push(disputeId);
        s.disputeProtocolFeeBps[disputeId] = s.stakeConfig.protocolFeeBps;
        s.disputeMinAppealStake[disputeId] = s.stakeConfig.minAppealStake;
        s.disputeEvidencePeriod[disputeId] = s.stakeConfig.evidencePeriod;
        s.disputeAppealPeriod[disputeId] = s.stakeConfig.appealPeriod;
        if (_token == address(0)) s.totalEscrowedNativeStake += _amount;
        _setRecordDisputed(s, _recordId);
        emit DisputeInitiated(disputeId, _recordId, msg.sender, _reason, _amount);
    }

    function respondToDispute(bytes32 _disputeId, string calldata _responseURI) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = _getExistingDispute(s, _disputeId);
        _expectStatus(dispute, _disputeId, AxiomTypesV2.DisputeStatus.PENDING);
        if (block.timestamp > dispute.deadline) {
            revert AxiomTypesV2.DisputeDeadlinePassed(_disputeId, dispute.deadline);
        }
        if (_getRecordOwner(s, dispute.recordId) != msg.sender) {
            revert AxiomTypesV2.UnauthorizedDisputeAction(_disputeId, msg.sender);
        }

        dispute.responseURI = _responseURI;
        dispute.status = AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD;
        dispute.deadline = _deadline(s.disputeEvidencePeriod[_disputeId]);
        emit DisputeResponseSubmitted(_disputeId, msg.sender, _responseURI);
    }

    function submitEvidence(bytes32 _disputeId, string calldata _evidenceURI) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = _getExistingDispute(s, _disputeId);
        _expectStatus(dispute, _disputeId, AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD);
        if (block.timestamp > dispute.deadline) {
            revert AxiomTypesV2.DisputeDeadlinePassed(_disputeId, dispute.deadline);
        }
        _requireParty(s, dispute, _disputeId);
        emit EvidenceSubmitted(_disputeId, msg.sender, _evidenceURI);
    }

    function escalateToArbitration(bytes32 _disputeId, address _arbitrator) external payable override nonReentrant {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = _getExistingDispute(s, _disputeId);
        _expectStatus(dispute, _disputeId, AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD);
        if (block.timestamp > dispute.deadline) {
            revert AxiomTypesV2.DisputeDeadlinePassed(_disputeId, dispute.deadline);
        }
        _requireParty(s, dispute, _disputeId);
        if (!s.approvedArbitrators[_arbitrator]) revert AxiomTypesV2.OperationNotPermitted();

        IArbitrator arbitrator = IArbitrator(_arbitrator);
        uint256 arbitrationFee = arbitrator.arbitrationCost("");
        if (msg.value < arbitrationFee) revert AxiomTypesV2.InsufficientFee(msg.value, arbitrationFee);

        dispute.status = AxiomTypesV2.DisputeStatus.ARBITRATION;
        dispute.arbitrator = _arbitrator;
        uint256 externalId = arbitrator.createDispute{value: arbitrationFee}(RULING_OPTIONS, "");
        if (s.externalDisputeMapping[_arbitrator][externalId] != bytes32(0)) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        dispute.externalDisputeId = bytes32(externalId);
        s.externalDisputeMapping[_arbitrator][externalId] = _disputeId;
        emit DisputeEscalated(_disputeId, _arbitrator, bytes32(externalId));
        _refund(msg.sender, msg.value - arbitrationFee);
    }

    function rule(uint256 _externalDisputeId, uint256 _ruling) external override {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        bytes32 disputeId = s.externalDisputeMapping[msg.sender][_externalDisputeId];
        if (disputeId == bytes32(0)) revert AxiomTypesV2.DisputeNotFound(disputeId);
        AxiomTypesV2.Dispute storage dispute = s.disputes[disputeId];
        if (dispute.arbitrator != msg.sender) {
            revert AxiomTypesV2.UnauthorizedDisputeAction(disputeId, msg.sender);
        }
        if (
            dispute.status != AxiomTypesV2.DisputeStatus.ARBITRATION
                && dispute.status != AxiomTypesV2.DisputeStatus.APPEALED
        ) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        if (_ruling == 0) {
            delete s.externalDisputeMapping[msg.sender][_externalDisputeId];
            dispute.externalDisputeId = bytes32(0);
            dispute.arbitrator = address(0);
            dispute.status = AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD;
            dispute.resolvedAt = 0;
            dispute.deadline = _deadline(s.disputeEvidencePeriod[disputeId]);
            delete s.disputeAppealDeadlines[disputeId];
            _setRecordDisputed(s, dispute.recordId);
            emit RulingRefused(disputeId, msg.sender);
            return;
        }
        if (_ruling != RULING_CHALLENGER && _ruling != RULING_OWNER) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        AxiomTypesV2.DisputeStatus newStatus = _ruling == RULING_CHALLENGER
            ? AxiomTypesV2.DisputeStatus.RESOLVED_VALID
            : AxiomTypesV2.DisputeStatus.RESOLVED_INVALID;
        address winner = _ruling == RULING_CHALLENGER ? dispute.challenger : _getRecordOwner(s, dispute.recordId);
        delete s.externalDisputeMapping[msg.sender][_externalDisputeId];
        dispute.status = newStatus;
        dispute.resolvedAt = uint40(block.timestamp);
        if (!s.disputeAppealUsed[disputeId] && dispute.stakeToken == address(0)) {
            s.disputeAppealDeadlines[disputeId] = _deadline(s.disputeAppealPeriod[disputeId]);
            _setRecordDisputed(s, dispute.recordId);
        } else {
            delete s.disputeAppealDeadlines[disputeId];
            _syncRecordAfterResolution(s, dispute.recordId, _ruling == RULING_CHALLENGER);
        }
        emit DisputeResolved(disputeId, newStatus, winner);
    }

    function resolveByTimeout(bytes32 _disputeId) external override nonReentrant {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = _getExistingDispute(s, _disputeId);
        if (block.timestamp <= dispute.deadline) revert AxiomTypesV2.OperationNotPermitted();

        if (dispute.status == AxiomTypesV2.DisputeStatus.PENDING) {
            dispute.status = AxiomTypesV2.DisputeStatus.RESOLVED_VALID;
            dispute.resolvedAt = uint40(block.timestamp);
            _syncRecordAfterResolution(s, dispute.recordId, true);
            emit DisputeResolved(_disputeId, dispute.status, dispute.challenger);
        } else if (dispute.status == AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD) {
            dispute.status = AxiomTypesV2.DisputeStatus.RESOLVED_INVALID;
            dispute.resolvedAt = uint40(block.timestamp);
            address owner = _getRecordOwner(s, dispute.recordId);
            _syncRecordAfterResolution(s, dispute.recordId, false);
            emit DisputeResolved(_disputeId, dispute.status, owner);
        } else {
            revert AxiomTypesV2.OperationNotPermitted();
        }
    }

    function settleDispute(
        bytes32 _disputeId,
        uint16 _challengerShare,
        bytes calldata _ownerSignature,
        bytes calldata _challengerSignature
    ) external override nonReentrant {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = _getExistingDispute(s, _disputeId);
        if (
            (dispute.status != AxiomTypesV2.DisputeStatus.PENDING
                    && dispute.status != AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD)
                || _challengerShare > BPS_DENOMINATOR
        ) {
            revert AxiomTypesV2.OperationNotPermitted();
        }

        address owner = _getRecordOwner(s, dispute.recordId);
        bytes32 digest = settlementDigest(_disputeId, _challengerShare);
        if (
            !SignatureChecker.isValidSignatureNowCalldata(owner, digest, _ownerSignature)
                || !SignatureChecker.isValidSignatureNowCalldata(dispute.challenger, digest, _challengerSignature)
        ) {
            revert AxiomTypesV2.UnauthorizedDisputeAction(_disputeId, msg.sender);
        }

        uint256 stakeAmount = dispute.stakeAmount;
        dispute.stakeAmount = 0;
        if (dispute.stakeToken == address(0)) s.totalEscrowedNativeStake -= stakeAmount;
        dispute.status = AxiomTypesV2.DisputeStatus.SETTLED;
        dispute.resolvedAt = uint40(block.timestamp);
        s.disputeSettlementChallengerShare[_disputeId] = _challengerShare;
        _syncRecordAfterResolution(s, dispute.recordId, false);

        uint256 challengerAmount = (stakeAmount * _challengerShare) / BPS_DENOMINATOR;
        _transferStake(dispute.stakeToken, dispute.challenger, challengerAmount);
        _transferStake(dispute.stakeToken, owner, stakeAmount - challengerAmount);
        emit DisputeSettled(_disputeId, _challengerShare, uint16(BPS_DENOMINATOR - _challengerShare));
    }

    function settlementDigest(bytes32 _disputeId, uint16 _challengerShare) public view override returns (bytes32) {
        return keccak256(abi.encode(SETTLEMENT_TYPEHASH, address(this), block.chainid, _disputeId, _challengerShare))
            .toEthSignedMessageHash();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                           CLAIMS AND APPEALS
    // ═══════════════════════════════════════════════════════════════════════════

    function claimStake(bytes32 _disputeId) external override nonReentrant returns (uint256 amount) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = _getExistingDispute(s, _disputeId);
        if (
            dispute.status != AxiomTypesV2.DisputeStatus.RESOLVED_VALID
                && dispute.status != AxiomTypesV2.DisputeStatus.RESOLVED_INVALID
        ) revert AxiomTypesV2.OperationNotPermitted();

        uint40 appealDeadline = s.disputeAppealDeadlines[_disputeId];
        if (appealDeadline != 0 && block.timestamp <= appealDeadline) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        if (dispute.stakeAmount == 0) return 0;

        address winner = dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_VALID
            ? dispute.challenger
            : _getRecordOwner(s, dispute.recordId);
        if (msg.sender != winner) revert AxiomTypesV2.UnauthorizedDisputeAction(_disputeId, msg.sender);

        uint256 stakeAmount = dispute.stakeAmount;
        dispute.stakeAmount = 0;
        if (dispute.stakeToken == address(0)) s.totalEscrowedNativeStake -= stakeAmount;
        _syncRecordAfterResolution(s, dispute.recordId, dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_VALID);
        uint256 protocolFee = (stakeAmount * s.disputeProtocolFeeBps[_disputeId]) / BPS_DENOMINATOR;
        amount = stakeAmount - protocolFee;
        _transferStake(dispute.stakeToken, winner, amount);
        _transferStake(dispute.stakeToken, s.treasuryWallet, protocolFee);
        emit StakeClaimed(_disputeId, msg.sender, amount);
    }

    function appeal(bytes32 _disputeId, string calldata _appealReason)
        external
        payable
        override
        nonReentrant
        returns (bytes32 appealId)
    {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        AxiomTypesV2.Dispute storage dispute = _getExistingDispute(s, _disputeId);
        if (
            dispute.status != AxiomTypesV2.DisputeStatus.RESOLVED_VALID
                && dispute.status != AxiomTypesV2.DisputeStatus.RESOLVED_INVALID
        ) revert AxiomTypesV2.OperationNotPermitted();

        uint40 deadline = s.disputeAppealDeadlines[_disputeId];
        if (
            deadline == 0 || block.timestamp > deadline || dispute.arbitrator == address(0)
                || dispute.stakeToken != address(0) || s.disputeAppealUsed[_disputeId]
        ) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
        address loser = dispute.status == AxiomTypesV2.DisputeStatus.RESOLVED_VALID
            ? _getRecordOwner(s, dispute.recordId)
            : dispute.challenger;
        if (msg.sender != loser) revert AxiomTypesV2.UnauthorizedDisputeAction(_disputeId, msg.sender);

        IArbitrator arbitrator = IArbitrator(dispute.arbitrator);
        uint256 externalId = uint256(dispute.externalDisputeId);
        uint256 appealFee = arbitrator.appealCost(externalId, "");
        uint256 appealBond = s.disputeMinAppealStake[_disputeId];
        uint256 requiredFee = appealFee + appealBond;
        if (msg.value < requiredFee) revert AxiomTypesV2.InsufficientFee(msg.value, requiredFee);

        appealId = keccak256(abi.encode(address(this), block.chainid, _disputeId, msg.sender, _appealReason));
        dispute.status = AxiomTypesV2.DisputeStatus.APPEALED;
        dispute.resolvedAt = 0;
        dispute.stakeAmount += appealBond;
        s.totalEscrowedNativeStake += appealBond;
        s.disputeAppealUsed[_disputeId] = true;
        delete s.disputeAppealDeadlines[_disputeId];
        _setRecordDisputed(s, dispute.recordId);
        // The first ruling clears the callback mapping so a stale arbitrator
        // callback cannot be replayed. An appeal starts a new ruling round for
        // the same external case, so restore the mapping before calling the
        // arbitrator. If the external call reverts, the whole transaction is
        // rolled back and no mapping is left behind.
        s.externalDisputeMapping[dispute.arbitrator][externalId] = _disputeId;
        arbitrator.appeal{value: appealFee}(externalId, bytes(_appealReason));
        _refund(msg.sender, msg.value - requiredFee);
        emit DisputeAppealed(_disputeId, appealId, msg.sender, appealBond);
    }

    function getAppealDeadline(bytes32 _disputeId) external view override returns (uint256 remainingSeconds) {
        uint40 deadline = AxiomStorage.getStorage().disputeAppealDeadlines[_disputeId];
        return deadline > block.timestamp ? deadline - block.timestamp : 0;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                                QUERIES
    // ═══════════════════════════════════════════════════════════════════════════

    function getDispute(bytes32 _disputeId) external view override returns (AxiomTypesV2.Dispute memory) {
        return AxiomStorage.getStorage().disputes[_disputeId];
    }

    function getDisputesByRecord(bytes32 _recordId) external view override returns (bytes32[] memory) {
        return AxiomStorage.getStorage().recordDisputes[_recordId];
    }

    function getDisputesByChallenger(address _challenger) external view override returns (bytes32[] memory) {
        return AxiomStorage.getStorage().challengerDisputes[_challenger];
    }

    function getActiveDisputes(uint256 _offset, uint256 _limit)
        external
        view
        override
        returns (bytes32[] memory disputeIds)
    {
        if (_limit == 0) return new bytes32[](0);
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        uint256 activeSeen;
        uint256 resultCount;
        for (uint256 i = 0; i < s.allDisputeIds.length && resultCount < _limit; i++) {
            bytes32 disputeId = s.allDisputeIds[i];
            if (!_isActive(s.disputes[disputeId].status)) continue;
            if (activeSeen++ < _offset) continue;
            resultCount++;
        }

        disputeIds = new bytes32[](resultCount);
        activeSeen = 0;
        uint256 cursor;
        for (uint256 i = 0; i < s.allDisputeIds.length && cursor < resultCount; i++) {
            bytes32 disputeId = s.allDisputeIds[i];
            if (!_isActive(s.disputes[disputeId].status)) continue;
            if (activeSeen++ < _offset) continue;
            disputeIds[cursor++] = disputeId;
        }
    }

    function hasActiveDispute(bytes32 _recordId) public view override returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        bytes32[] storage ids = s.recordDisputes[_recordId];
        return ids.length != 0 && _isActive(s.disputes[ids[ids.length - 1]].status);
    }

    function getStakeConfig() external view override returns (AxiomTypesV2.StakeConfig memory) {
        return AxiomStorage.getStorage().stakeConfig;
    }

    function getMinimumStake(bytes32) external view override returns (uint256) {
        return AxiomStorage.getStorage().stakeConfig.minStakeAmount;
    }

    function getApprovedArbitrators() external view override returns (address[] memory arbitrators) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        uint256 count;
        for (uint256 i = 0; i < s.arbitratorList.length; i++) {
            if (s.approvedArbitrators[s.arbitratorList[i]]) count++;
        }
        arbitrators = new address[](count);
        uint256 cursor;
        for (uint256 i = 0; i < s.arbitratorList.length; i++) {
            address arbitrator = s.arbitratorList[i];
            if (s.approvedArbitrators[arbitrator]) arbitrators[cursor++] = arbitrator;
        }
    }

    function isArbitratorApproved(address _arbitrator) external view override returns (bool) {
        return AxiomStorage.getStorage().approvedArbitrators[_arbitrator];
    }

    function getArbitratorFee(address _arbitrator, AxiomTypesV2.DisputeReason)
        external
        view
        override
        returns (uint256)
    {
        return IArbitrator(_arbitrator).arbitrationCost("");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                              INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    function _requireConfigured(AxiomStorage.Storage storage s) internal view {
        if (!s.disputeSystemInitialized || s.stakeConfig.minStakeAmount == 0) {
            revert AxiomTypesV2.OperationNotPermitted();
        }
    }

    function _getExistingDispute(AxiomStorage.Storage storage s, bytes32 _disputeId)
        internal
        view
        returns (AxiomTypesV2.Dispute storage dispute)
    {
        dispute = s.disputes[_disputeId];
        if (dispute.disputeId == bytes32(0)) revert AxiomTypesV2.DisputeNotFound(_disputeId);
    }

    function _expectStatus(
        AxiomTypesV2.Dispute storage dispute,
        bytes32 _disputeId,
        AxiomTypesV2.DisputeStatus _expected
    ) internal view {
        if (dispute.status != _expected) {
            revert AxiomTypesV2.InvalidDisputeStatus(_disputeId, _expected, dispute.status);
        }
    }

    function _requireParty(AxiomStorage.Storage storage s, AxiomTypesV2.Dispute storage dispute, bytes32 _disputeId)
        internal
        view
    {
        if (msg.sender != dispute.challenger && msg.sender != _getRecordOwner(s, dispute.recordId)) {
            revert AxiomTypesV2.UnauthorizedDisputeAction(_disputeId, msg.sender);
        }
    }

    function _requireActiveRecord(AxiomStorage.Storage storage s, bytes32 _recordId)
        internal
        view
        returns (address owner)
    {
        if (AxiomStorage.recordExistsV2(_recordId)) {
            AxiomTypesV2.AxiomRecord storage recordV2 = s.recordsV2[_recordId];
            if (recordV2.status != AxiomTypesV2.ContentStatus.ACTIVE) {
                revert AxiomTypesV2.InvalidContentStatus(_recordId, recordV2.status);
            }
            return recordV2.issuer;
        }
        if (AxiomStorage.recordExists(_recordId)) {
            AxiomTypes.AxiomRecord storage recordV1 = s.records[_recordId];
            if (recordV1.status != AxiomTypes.ContentStatus.ACTIVE) {
                revert AxiomTypesV2.OperationNotPermitted();
            }
            return recordV1.issuer;
        }
        revert AxiomTypesV2.ContentNotFound(_recordId);
    }

    function _getRecordOwner(AxiomStorage.Storage storage s, bytes32 _recordId) internal view returns (address) {
        if (AxiomStorage.recordExistsV2(_recordId)) return s.recordsV2[_recordId].issuer;
        if (AxiomStorage.recordExists(_recordId)) return s.records[_recordId].issuer;
        revert AxiomTypesV2.ContentNotFound(_recordId);
    }

    function _setRecordDisputed(AxiomStorage.Storage storage s, bytes32 _recordId) internal {
        if (AxiomStorage.recordExistsV2(_recordId)) {
            s.recordsV2[_recordId].status = AxiomTypesV2.ContentStatus.DISPUTED;
        } else {
            s.records[_recordId].status = AxiomTypes.ContentStatus.DISPUTED;
        }
    }

    function _syncRecordAfterResolution(AxiomStorage.Storage storage s, bytes32 _recordId, bool _challengerWon)
        internal
    {
        if (AxiomStorage.recordExistsV2(_recordId)) {
            s.recordsV2[_recordId].status =
                _challengerWon ? AxiomTypesV2.ContentStatus.BANNED : AxiomTypesV2.ContentStatus.ACTIVE;
        } else {
            // V1 has no BANNED value; DISPUTED is terminal when the challenger wins.
            s.records[_recordId].status =
                _challengerWon ? AxiomTypes.ContentStatus.DISPUTED : AxiomTypes.ContentStatus.ACTIVE;
        }
    }

    function _transferStake(address _token, address _to, uint256 _amount) internal {
        if (_amount == 0) return;
        if (_to == address(0)) revert AxiomTypesV2.ZeroAddress();
        if (_token == address(0)) {
            (bool success,) = payable(_to).call{value: _amount}("");
            require(success, "DisputeFacet: ETH transfer failed");
        } else {
            IERC20(_token).safeTransfer(_to, _amount);
        }
    }

    function _refund(address _to, uint256 _amount) internal {
        if (_amount == 0) return;
        (bool success,) = payable(_to).call{value: _amount}("");
        require(success, "DisputeFacet: refund failed");
    }

    function _deadline(uint40 _period) internal view returns (uint40 deadline) {
        uint256 value = block.timestamp + uint256(_period);
        if (value > type(uint40).max) revert AxiomTypesV2.OperationNotPermitted();
        deadline = uint40(value);
    }

    function _isActive(AxiomTypesV2.DisputeStatus _status) internal pure returns (bool) {
        return _status == AxiomTypesV2.DisputeStatus.PENDING || _status == AxiomTypesV2.DisputeStatus.EVIDENCE_PERIOD
            || _status == AxiomTypesV2.DisputeStatus.ARBITRATION || _status == AxiomTypesV2.DisputeStatus.APPEALED;
    }

    event StakeConfigUpdated(address indexed stakeToken, uint256 minStakeAmount);
    event ArbitratorApprovalUpdated(address indexed arbitrator, bool approved);
    event RulingRefused(bytes32 indexed disputeId, address indexed arbitrator);
}
