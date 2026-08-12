// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AxiomStorage} from "../storage/AxiomStorage.sol";

interface IDisputeSetupRouterAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

/**
 * @notice Backward-compatible initializer for deployments that cannot configure
 *         StakeConfig atomically. New deployments should route configureStakeConfig
 *         from AxiomDisputeFacet instead of installing this facet.
 */
contract AxiomDisputeSetupFacet {
    bytes32 private constant DEFAULT_ADMIN_ROLE = 0x00;

    modifier onlyAdmin() {
        require(
            IDisputeSetupRouterAccessControl(address(this)).hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "DisputeSetupFacet: missing admin role"
        );
        _;
    }

    function initializeDisputeSystem() external onlyAdmin {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();

        // Idempotent without allowing a caller to reset governance configuration.
        if (s.disputeSystemInitialized) return;

        s.stakeConfig.minStakeAmount = 0.01 ether;
        s.stakeConfig.minAppealStake = 0.02 ether;
        s.stakeConfig.stakeToken = address(0);
        s.stakeConfig.protocolFeeBps = 500;
        s.stakeConfig.rewardBps = 0;
        s.stakeConfig.slashBps = 0;
        s.stakeConfig.responsePeriod = 3 days;
        s.stakeConfig.evidencePeriod = 3 days;
        s.stakeConfig.appealPeriod = 3 days;
        s.disputeSystemInitialized = true;
    }
}
