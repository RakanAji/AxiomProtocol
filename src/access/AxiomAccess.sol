// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {AxiomTypes} from "../libraries/AxiomTypes.sol";

/**
 * @title AxiomAccess
 * @author Axiom Protocol Team
 * @notice Role-based access control for Axiom Protocol
 * @dev Uses OpenZeppelin AccessControl with custom roles
 */
contract AxiomAccess is Initializable, AccessControlUpgradeable {
    // ============ Role Definitions ============

    /// @notice Operator role - can verify identities, dispute content
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    /// @notice Enterprise role - gets discounted fees, higher rate limits
    bytes32 public constant ENTERPRISE_ROLE = keccak256("ENTERPRISE_ROLE");
    
    /// @notice Pauser role - can pause/unpause protocol
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ============ Events ============

    event AddressBanned(address indexed user, string reason);
    event AddressUnbanned(address indexed user);
    event ContentDisputed(bytes32 indexed recordId, address indexed operator, string reason);
    event ProtocolPaused(address indexed by);
    event ProtocolUnpaused(address indexed by);
    event RateLimitUpdated(uint256 window, uint256 maxActions);

    // ============ Admin Functions ============

    /**
     * @notice Ban an address from using the protocol
     * @param _user Address to ban
     * @param _reason Reason for ban
     */
    function banAddress(address _user, string calldata _reason) external onlyRole(OPERATOR_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.bannedAddresses[_user] = true;
        emit AddressBanned(_user, _reason);
    }

    /**
     * @notice Unban an address
     * @param _user Address to unban
     */
    function unbanAddress(address _user) external onlyRole(OPERATOR_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.bannedAddresses[_user] = false;
        emit AddressUnbanned(_user);
    }

    /**
     * @notice Mark content as disputed
     * @param _recordId Record ID to dispute
     * @param _reason Reason for dispute
     */
    function disputeContent(bytes32 _recordId, string calldata _reason) external onlyRole(OPERATOR_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (!AxiomStorage.recordExists(_recordId)) {
            revert AxiomTypes.ContentNotFound(_recordId);
        }
        
        s.records[_recordId].status = AxiomTypes.ContentStatus.DISPUTED;
        
        emit ContentDisputed(_recordId, msg.sender, _reason);
        emit AxiomTypes.ContentDisputed(_recordId, msg.sender, _reason);
    }

    /**
     * @notice Pause the protocol
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.paused = true;
        emit ProtocolPaused(msg.sender);
    }

    /**
     * @notice Unpause the protocol
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.paused = false;
        emit ProtocolUnpaused(msg.sender);
    }

    /**
     * @notice Update rate limit settings
     * @param _window Time window in seconds
     * @param _maxActions Max actions per window
     */
    function setRateLimit(uint256 _window, uint256 _maxActions) external onlyRole(DEFAULT_ADMIN_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.rateLimitWindow = _window;
        s.maxActionsPerWindow = _maxActions;
        emit RateLimitUpdated(_window, _maxActions);
    }

    /**
     * @notice Set maximum batch size
     * @param _size New max batch size
     */
    function setMaxBatchSize(uint256 _size) external onlyRole(DEFAULT_ADMIN_ROLE) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.maxBatchSize = _size;
    }

    // ============ View Functions ============

    /**
     * @notice Check if address is banned
     * @param _user Address to check
     * @return banned Whether address is banned
     */
    function isBanned(address _user) external view returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.bannedAddresses[_user];
    }

    /**
     * @notice Check if protocol is paused
     * @return paused Whether protocol is paused
     */
    function isPaused() external view returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.paused;
    }

    /**
     * @notice Get rate limit settings
     * @return window Rate limit window in seconds
     * @return maxActions Max actions per window
     */
    function getRateLimitSettings() external view returns (uint256 window, uint256 maxActions) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return (s.rateLimitWindow, s.maxActionsPerWindow);
    }

    /**
     * @notice Get max batch size
     * @return size Max batch size
     */
    function getMaxBatchSize() external view returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.maxBatchSize;
    }
}
