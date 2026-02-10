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

### [H-03] Royalty distribution loop allows single recipient to block all license purchases (DoS)

**Severity:** High
**Location:** `src/core/AxiomLicenseNFT.sol` (Function: `_distributeRoyaltiesETH`)

**Description:**
The contract utilizes a "Push Payment" pattern to distribute royalties within a loop. When a license is purchased, the `_distributeRoyaltiesETH` function iterates through all recipients defined in the royalty split and attempts to send ETH using `.call`.

```solidity
// src/core/AxiomLicenseNFT.sol:74-75
(bool success,) = payable(_split.recipients[i]).call{value: share}("");
require(success, "Royalty transfer failed");
```
The strict check `require(success)` creates a critical vulnerability. If any single recipient in the list reverts the transaction (e.g., a smart contract without a `receive()` function, a malicious contract designed to revert, or a grieving attack), the entire purchase transaction will revert.

**Impact**: A single malicious or broken address in the royalty list causes a permanent Denial of Service (DoS) for that license. No user can purchase the license, locking revenue for all other recipients and the protocol.

**Proof of Concept (PoC)**: A test case demonstrated that adding a `BrokenRecipient` (which reverts on receipt) to the royalty split caused all subsequent `purchaseLicense` calls to fail. Reference: `test/LicenseAudit.t.sol` (Test: `testFinding_RoyaltyPoisoning`)

**Recommendation**: Adopt a "Pull over Push" strategy for failed transfers. If an ETH transfer fails, do not revert. Instead, record the failed amount in the existing `pendingRoyalties` mapping, allowing the recipient to withdraw it manually later via `claimRoyalties`.
```diff
- (bool success,) = payable(_split.recipients[i]).call{value: share}("");
- require(success, "Royalty transfer failed");
+ (bool success,) = payable(_split.recipients[i]).call{value: share}("");
+ if (!success) {
+     LicenseStorage storage s = _getLicenseStorage();
+     s.pendingRoyalties[address(0)][_split.recipients[i]] += share;
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

### [M-02] Identity update fails to update reverse-lookup mapping, causing data inconsistency

**Severity:** Medium
**Location:** `src/AxiomRouter.sol` (Function: `updateIdentity`)

**Description:**
The `updateIdentity` function updates the user's `Identity` struct (name and proofURI) but fails to update the critical `nameToAddress` reverse-lookup mapping.

```solidity
// src/AxiomRouter.sol:114-115
s.identities[msg.sender].name = _name;
s.identities[msg.sender].proofURI = _proofURI;
// Missing: s.nameToAddress mapping update!
```
**Impact**:
1. **Ghost Name**: The user's old name remains permanently linked to their address in `nameToAddress`, preventing others from claiming it.
2. **Unresolvable New Name**: The new name is not registered in `nameToAddress`. Calling `resolveByName(newName)` returns `address(0)`, making the user invisible to name resolution lookups despite having a valid identity struct.

**Proof of Concept (PoC)**: A test case confirmed that after calling `updateIdentity("SuperUser")`, resolving "SuperUser" returns `0x0`, while resolving the old name "AxiomUser" still returns the user's address. Reference: `test/IdentityAudit.t.sol` (Test: `testFinding_IdentityInconsistency`)

**Recommendation**: The `updateIdentity` function must:
1. Delete the mapping for the old name.
2. Set the mapping for the new name to `msg.sender`.
3. Ensure the new name is not already taken.
```solidity
function updateIdentity(string calldata _name, string calldata _proofURI) external override notBanned {
    AxiomStorage.Storage storage s = AxiomStorage.getStorage();
    require(bytes(_name).length > 0, "Name empty");
    
    // 1. Check consistency
    string memory oldName = s.identities[msg.sender].name;
    require(keccak256(bytes(oldName)) != keccak256(bytes(_name)), "Same name");
    require(s.nameToAddress[_name] == address(0), "Name taken");

    // 2. Update Mappings
    s.nameToAddress[oldName] = address(0); // Free up old name
    s.nameToAddress[_name] = msg.sender;   // Reserve new name

    // 3. Update Struct
    s.identities[msg.sender].name = _name;
    s.identities[msg.sender].proofURI = _proofURI;
    
    emit AxiomTypes.IdentityRegistered(msg.sender, _name, _proofURI);
}
```

