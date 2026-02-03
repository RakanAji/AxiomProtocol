// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {AxiomTypes} from "../libraries/AxiomTypes.sol";
import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {IAxiomTreasury} from "../interfaces/IAxiomTreasury.sol";

/**
 * @title AxiomTreasury
 * @author Axiom Protocol Team
 * @notice Treasury management for fee collection and distribution
 */
contract AxiomTreasury is Initializable, IAxiomTreasury {
    // ============ Modifiers ============

    /**
     * @dev Ensures caller has admin role (checked via router)
     */
    modifier onlyAdmin() {
        // This will be enforced by AxiomRouter via access control
        _;
    }

    // ============ External Functions ============

    /**
     * @inheritdoc IAxiomTreasury
     */
    function setBaseFee(uint256 _fee) external override onlyAdmin {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.baseFee = _fee;
    }

    /**
     * @inheritdoc IAxiomTreasury
     */
    function setEnterpriseRate(address _user, uint256 _rate) external override onlyAdmin {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.enterpriseRates[_user] = _rate;
    }

    /**
     * @inheritdoc IAxiomTreasury
     */
    function grantEnterpriseStatus(address _user) external override onlyAdmin {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.isEnterprise[_user] = true;
    }

    /**
     * @inheritdoc IAxiomTreasury
     */
    function revokeEnterpriseStatus(address _user) external override onlyAdmin {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.isEnterprise[_user] = false;
    }

    /**
     * @inheritdoc IAxiomTreasury
     */
    function withdraw(address _to, uint256 _amount) external override onlyAdmin {
        require(_to != address(0), "Invalid recipient");
        require(address(this).balance >= _amount, "Insufficient balance");
        
        (bool success,) = payable(_to).call{value: _amount}("");
        require(success, "Transfer failed");
    }

    /**
     * @inheritdoc IAxiomTreasury
     */
    function setTreasuryWallet(address _wallet) external override onlyAdmin {
        require(_wallet != address(0), "Invalid address");
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        s.treasuryWallet = _wallet;
    }

    // ============ View Functions ============

    /**
     * @inheritdoc IAxiomTreasury
     */
    function getFee(address _user) external view override returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        
        if (s.isEnterprise[_user] && s.enterpriseRates[_user] > 0) {
            return s.enterpriseRates[_user];
        }
        
        return s.baseFee;
    }

    /**
     * @inheritdoc IAxiomTreasury
     */
    function getBaseFee() external view override returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.baseFee;
    }

    /**
     * @inheritdoc IAxiomTreasury
     */
    function getTotalFeesCollected() external view override returns (uint256) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.totalFeesCollected;
    }

    /**
     * @inheritdoc IAxiomTreasury
     */
    function isEnterpriseUser(address _user) external view override returns (bool) {
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        return s.isEnterprise[_user];
    }
}
