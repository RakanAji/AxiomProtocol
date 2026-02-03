// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IAxiomTreasury
 * @notice Interface for treasury and fee management
 */
interface IAxiomTreasury {
    /**
     * @notice Get the fee for a specific user
     * @param _user Address to check fee for
     * @return fee The fee amount in wei
     */
    function getFee(address _user) external view returns (uint256 fee);

    /**
     * @notice Set the base fee (Admin only)
     * @param _fee New base fee in wei
     */
    function setBaseFee(uint256 _fee) external;

    /**
     * @notice Set enterprise rate for specific address (Admin only)
     * @param _user Enterprise address
     * @param _rate Custom rate in wei
     */
    function setEnterpriseRate(address _user, uint256 _rate) external;

    /**
     * @notice Grant enterprise status (Admin only)
     * @param _user Address to grant enterprise status
     */
    function grantEnterpriseStatus(address _user) external;

    /**
     * @notice Revoke enterprise status (Admin only)
     * @param _user Address to revoke enterprise status
     */
    function revokeEnterpriseStatus(address _user) external;

    /**
     * @notice Withdraw collected fees (Admin only)
     * @param _to Recipient address
     * @param _amount Amount to withdraw
     */
    function withdraw(address _to, uint256 _amount) external;

    /**
     * @notice Set treasury wallet address (Admin only)
     * @param _wallet New treasury wallet
     */
    function setTreasuryWallet(address _wallet) external;

    /**
     * @notice Get current base fee
     * @return fee Base fee in wei
     */
    function getBaseFee() external view returns (uint256 fee);

    /**
     * @notice Get total fees collected
     * @return total Total fees collected
     */
    function getTotalFeesCollected() external view returns (uint256 total);

    /**
     * @notice Check if address has enterprise status
     * @param _user Address to check
     * @return isEnterprise Whether address has enterprise status
     */
    function isEnterpriseUser(address _user) external view returns (bool isEnterprise);
}
