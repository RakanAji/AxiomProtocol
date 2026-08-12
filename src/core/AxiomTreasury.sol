// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {AxiomTypes} from "../libraries/AxiomTypes.sol";
import {AxiomStorage} from "../storage/AxiomStorage.sol";
import {IAxiomTreasury} from "../interfaces/IAxiomTreasury.sol";

interface IRouterAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

/**
 * @title AxiomTreasury
 * @author Axiom Protocol Team
 * @notice Treasury management for fee collection and distribution
 */
contract AxiomTreasury is Initializable, IAxiomTreasury {
    bytes32 private constant DEFAULT_ADMIN_ROLE = 0x00;

    // ============ Modifiers ============

    /**
     * @dev Ensures caller has admin role (checked via router)
     */
    modifier onlyAdmin() {
        require(
            IRouterAccessControl(address(this)).hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "AxiomTreasury: missing admin role"
        );
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
        AxiomStorage.Storage storage s = AxiomStorage.getStorage();
        uint256 available = address(this).balance - s.totalEscrowedNativeStake;
        require(available >= _amount, "Insufficient unreserved balance");

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
