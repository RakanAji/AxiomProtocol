# Axiom Protocol Security Audit Report

**Prepared by:** Rakan Aji
**Date:** February 10, 2026
**Target:** AxiomRouter.sol & Core Contracts

## 1. Executive Summary

This report presents the results of a security audit conducted on the **Axiom Protocol**, specifically focusing on the Router architecture. The audit aimed to identify potential security vulnerabilities, logic errors, and gas optimization issues.

The audit uncovered **2 significant vulnerabilities** involving fund management and denial of service risks.

## 2. Findings Summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| [H-01] | Funds permanently locked when withdrawing to Smart Contracts due to gas limit | **High** | Fixed |
| [M-01] | Strict check on ETH refund causes Denial of Service for specific users | **Medium** | Fixed |

---

## 3. Detailed Findings

### [H-01] Funds permanently locked when withdrawing to Smart Contracts due to `.transfer()` gas limit

**Severity:** High
**Location:** `AxiomRouter.sol` (Function: `withdraw`)

**Description:**
The `withdraw` function utilizes the legacy Solidity method `.transfer()` to send ETH to the treasury address.

```solidity
payable(_to).transfer(_amount);
```
The `.transfer()` method forwards a fixed amount of 2300 gas to the recipient. This amount is sufficient for transfers to EOA (Externally Owned Accounts) but is often insufficient for transfers to Smart Contracts (e.g., Gnosis Safe Multisig, Argent, or DAOs) which may require more gas to execute logic in their receive() or fallback() functions (such as emitting events or writing to storage).

**Impact**: If the protocol sets the Treasury Wallet address to a Smart Contract (Multisig), the withdraw function will consistently revert due to "Out of Gas". Consequently, all protocol fees collected in the Router contract will be permanently frozen, as the Admin is unable to extract them.

**Proof of Concept (PoC)**: A test case was created using a HeavyWallet mock that consumes >2300 gas upon receipt. The test confirmed that withdraw reverts when targeting this wallet. Reference: `test/RealAudit.t.sol` (Test: testFinding_WithdrawTrap)

**Recommendation**: Replace `.transfer()` with `.call` to forward all available gas, and use the "Check-Effects-Interactions" pattern.

```diff
- payable(_to).transfer(_amount);
+ (bool success, ) = payable(_to).call{value: _amount}("");
+ require(success, "Withdraw transfer failed");
```
### [H-02] Unprotected `onlyAdmin` modifier allows unauthorized treasury drainage

**Severity:** Critical
**Location:** `src/core/AxiomTreasury.sol` (Modifier: `onlyAdmin`)

**Description:**
The `onlyAdmin` modifier, intended to restrict sensitive functions like `withdraw` and `setBaseFee`, is implemented with an **empty body**.

```solidity
// src/core/AxiomTreasury.sol:19-22
modifier onlyAdmin() {
    // This will be enforced by AxiomRouter via access control
    _; // <--- Vulnerability: No check performed!
}
```
While the comment suggests that access control is enforced by the Router, this assumption fails if `AxiomTreasury` is deployed as a standalone contract or initialized independently. Since the modifier does not perform any check on `msg.sender`, any external user can call the protected functions.

**Impact**: A malicious actor can call `withdraw(attacker, amount)` directly on the Treasury contract and drain 100% of the protocol's funds. They can also manipulate fee parameters (`setBaseFee`) to disrupt the protocol.

**Proof of Concept (PoC)**: A test case confirmed that an unauthorized address (`hacker`) could successfully withdraw 100 ETH from the Treasury. Reference: `test/TreasuryAudit.t.sol` (Test: `testFinding_TreasuryDrain`)

**Recommendation**: Implement proper Access Control checks within the modifier. Since the system uses OpenZeppelin's `AccessControl`, the contract should inherit `AccessControlUpgradeable` and check the `DEFAULT_ADMIN_ROLE`.
```diff
- modifier onlyAdmin() {
-     // This will be enforced by AxiomRouter via access control
-     _;
- }
+ modifier onlyAdmin() {
+     _checkRole(DEFAULT_ADMIN_ROLE, msg.sender);
+     _;
+ }
```

### [M-01] Strict check on ETH refund causes Denial of Service for smart contract users
**Severity:** High
**Location:** `AxiomRouter.sol` (Function: `register, batchRegister`)

**Description**
The `register` function includes logic to refund excess ETH sent by the user. The contract strictly enforces that this refund must succeed:
```solidity
if (msg.value > requiredFee) {
    (bool success,) = payable(msg.sender).call{value: msg.value - requiredFee}("");
    require(success, "Refund failed"); // <--- VULNERABILITY
}
```
If `msg.sender` is a Smart Contract that cannot receive ETH (e.g., lacks a receive function or intentionally reverts), the refund call will fail. Due to the require(success) check, the failure of the refund propagates and causes the entire registration transaction to revert.

**Impact**: Users operating through specific Smart Wallets or DAO executors will be effectively blocked (Denial of Service) from using the protocol if they inadvertently send more ETH than the exact fee. While funds are not lost, this severely limits protocol composability and adoption.

**Proof of Concept (PoC)**: A test case was created using a RevertingWallet mock. The test confirmed that registration fails if the user overpays, preventing legitimate usage. Reference: `test/RealAudit.t.sol` (Test: testFinding_StrictRefundDoS)

**Recommendation**: Remove the strict requirement for the refund to succeed. If the refund fails, the excess ETH should remain in the contract (or be credited to a pending balance) rather than blocking the main transaction.
```diff
if (msg.value > requiredFee) {
-   (bool success,) = payable(msg.sender).call{value: msg.value - requiredFee}("");
-   require(success, "Refund failed");
+   // Attempt to refund but do not block execution if it fails
+   payable(msg.sender).call{value: msg.value - requiredFee}(""); 
}
```