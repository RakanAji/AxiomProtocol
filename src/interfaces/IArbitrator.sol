// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IArbitrator
 * @author Axiom Protocol Team
 * @notice Standard interface for Arbitrator (e.g. Kleros, Aragon)
 */
interface IArbitrator {
    /**
     * @notice Create a dispute. Must be called by the arbitrable contract.
     * @param _choices Amount of choices the arbitrator can make in this dispute.
     * @param _extraData Can be used to give additional info on the dispute to be created.
     * @return disputeID ID of the dispute created.
     */
    function createDispute(uint256 _choices, bytes calldata _extraData) external payable returns (uint256 disputeID);

    /**
     * @notice Compute the cost of arbitration. It is recommended not to increase it often, 
     *         as it can be highly time and gas consuming for the arbitrated contracts to cope with fee augmentation.
     * @param _extraData Can be used to give additional info on the dispute to be created.
     * @return cost Amount to be paid.
     */
    function arbitrationCost(bytes calldata _extraData) external view returns (uint256 cost);

    /**
     * @notice Appeal a ruling.
     * @param _disputeID ID of the dispute to be appealed.
     * @param _extraData Can be used to give additional info on the appeal.
     */
    function appeal(uint256 _disputeID, bytes calldata _extraData) external payable;

    /**
     * @notice Compute the cost of appeal. It is recommended not to increase it often, 
     *         as it can be highly time and gas consuming for the arbitrated contracts to cope with fee augmentation.
     * @param _disputeID ID of the dispute to be appealed.
     * @param _extraData Can be used to give additional info on the appeal.
     * @return cost Amount to be paid.
     */
    function appealCost(uint256 _disputeID, bytes calldata _extraData) external view returns (uint256 cost);

    /**
     * @notice Compute the start and end of the dispute's current or next appeal period, if possible.
     * @param _disputeID ID of the dispute.
     * @return start The start of the period.
     * @return end The end of the period.
     */
    function appealPeriod(uint256 _disputeID) external view returns (uint256 start, uint256 end);
}
