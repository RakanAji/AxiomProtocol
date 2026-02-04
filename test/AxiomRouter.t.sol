// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AxiomRouter} from "../src/AxiomRouter.sol";
import {AxiomTypes} from "../src/libraries/AxiomTypes.sol";
import {AxiomStorage} from "../src/storage/AxiomStorage.sol";

/**
 * @title AxiomRouterTest
 * @notice Comprehensive test suite for Axiom Protocol
 */
contract AxiomRouterTest is Test {
    AxiomRouter public axiom;
    AxiomRouter public axiomImpl;
    
    address public admin = address(1);
    address public treasury = address(2);
    address public user1 = address(3);
    address public user2 = address(4);
    address public operator = address(5);
    address public enterprise = address(6);
    
    uint256 public constant BASE_FEE = 0.0001 ether;
    
    // Sample content hashes
    bytes32 public contentHash1 = keccak256("content1");
    bytes32 public contentHash2 = keccak256("content2");
    bytes32 public contentHash3 = keccak256("content3");
    
    // Events for testing
    event ContentRegistered(
        bytes32 indexed recordId,
        address indexed issuer,
        bytes32 contentHash,
        uint40 timestamp,
        string metadataURI
    );
    
    event ContentRevoked(
        bytes32 indexed recordId,
        address indexed issuer,
        string reason
    );
    
    event IdentityRegistered(
        address indexed user,
        string name,
        string proofURI
    );

    function setUp() public {
        // Deploy implementation
        axiomImpl = new AxiomRouter();
        
        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            AxiomRouter.initialize.selector,
            admin,
            treasury
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(axiomImpl), initData);
        axiom = AxiomRouter(payable(address(proxy)));
        
        // Get the operator role bytes32 BEFORE pranking
        bytes32 operatorRole = axiom.OPERATOR_ROLE();
        
        // Setup operator role - prank then call (prank won't be consumed by view call now)
        vm.prank(admin);
        axiom.grantRole(operatorRole, operator);
        
        // Fund test users
        vm.deal(user1, 10 ether);
        vm.deal(user2, 10 ether);
        vm.deal(enterprise, 10 ether);
    }

    // ============ Initialization Tests ============

    function test_Initialize() public view {
        assertEq(axiom.VERSION(), "1.0.0");
        assertEq(axiom.getBaseFee(), BASE_FEE);
        assertTrue(axiom.hasRole(axiom.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(axiom.hasRole(axiom.OPERATOR_ROLE(), admin));
        assertTrue(axiom.hasRole(axiom.PAUSER_ROLE(), admin));
    }

    function test_CannotReinitialize() public {
        vm.expectRevert();
        axiom.initialize(address(10), address(11));
    }

    // ============ Registration Tests ============

    function test_Register() public {
        vm.startPrank(user1);
        
        bytes32 recordId = axiom.register{value: BASE_FEE}(
            contentHash1,
            "ipfs://QmTest123"
        );
        
        assertTrue(recordId != bytes32(0));
        
        // Verify record
        AxiomTypes.AxiomRecord memory record = axiom.getRecord(recordId);
        assertEq(record.issuer, user1);
        assertEq(record.contentHash, contentHash1);
        assertEq(uint8(record.status), uint8(AxiomTypes.ContentStatus.ACTIVE));
        
        vm.stopPrank();
    }

    function test_Register_EmitsEvent() public {
        vm.startPrank(user1);
        
        bytes32 expectedRecordId = AxiomStorage.generateRecordId(contentHash1, user1);
        
        vm.expectEmit(true, true, false, true);
        emit ContentRegistered(
            expectedRecordId,
            user1,
            contentHash1,
            uint40(block.timestamp),
            "ipfs://QmTest123"
        );
        
        axiom.register{value: BASE_FEE}(contentHash1, "ipfs://QmTest123");
        
        vm.stopPrank();
    }

    function test_Register_RefundsExcess() public {
        uint256 balanceBefore = user1.balance;
        
        vm.prank(user1);
        axiom.register{value: 1 ether}(contentHash1, "");
        
        uint256 balanceAfter = user1.balance;
        assertEq(balanceBefore - balanceAfter, BASE_FEE);
    }

    function test_Register_RevertsOnDuplicate() public {
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "");
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.register{value: BASE_FEE}(contentHash1, "");
    }

    function test_Register_RevertsOnInsufficientFee() public {
        vm.prank(user1);
        vm.expectRevert();
        axiom.register{value: BASE_FEE / 2}(contentHash1, "");
    }

    function test_DifferentUsersSameHash() public {
        // Different users CAN register the same hash (each binds to their identity)
        vm.prank(user1);
        bytes32 record1 = axiom.register{value: BASE_FEE}(contentHash1, "");
        
        vm.prank(user2);
        bytes32 record2 = axiom.register{value: BASE_FEE}(contentHash1, "");
        
        assertTrue(record1 != record2);
        assertEq(axiom.getRecord(record1).issuer, user1);
        assertEq(axiom.getRecord(record2).issuer, user2);
    }

    // ============ Batch Registration Tests ============

    function test_BatchRegister() public {
        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = contentHash1;
        hashes[1] = contentHash2;
        hashes[2] = contentHash3;
        
        string[] memory uris = new string[](3);
        uris[0] = "ipfs://1";
        uris[1] = "ipfs://2";
        uris[2] = "ipfs://3";
        
        vm.prank(user1);
        bytes32[] memory recordIds = axiom.batchRegister{value: BASE_FEE * 3}(hashes, uris);
        
        assertEq(recordIds.length, 3);
        assertEq(axiom.getTotalRecords(), 3);
    }

    function test_BatchRegister_ArrayMismatch() public {
        bytes32[] memory hashes = new bytes32[](2);
        string[] memory uris = new string[](3);
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.batchRegister{value: BASE_FEE * 3}(hashes, uris);
    }

    // ============ Verification Tests ============

    function test_Verify() public {
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "ipfs://test");
        
        // Verify with correct issuer
        (bool isValid, AxiomTypes.AxiomRecord memory record) = axiom.verify(contentHash1, user1);
        
        assertTrue(isValid);
        assertEq(record.issuer, user1);
        assertEq(record.contentHash, contentHash1);
    }

    function test_Verify_WrongIssuer() public {
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "");
        
        // Verify with wrong issuer should fail
        (bool isValid,) = axiom.verify(contentHash1, user2);
        assertFalse(isValid);
    }

    function test_Verify_NonExistent() public {
        (bool isValid,) = axiom.verify(contentHash1, user1);
        assertFalse(isValid);
    }

    // ============ Revocation Tests ============

    function test_Revoke() public {
        vm.startPrank(user1);
        bytes32 recordId = axiom.register{value: BASE_FEE}(contentHash1, "");
        
        axiom.revoke(recordId, "Key compromised");
        
        AxiomTypes.AxiomRecord memory record = axiom.getRecord(recordId);
        assertEq(uint8(record.status), uint8(AxiomTypes.ContentStatus.REVOKED));
        
        // Verify should now return false
        (bool isValid,) = axiom.verify(contentHash1, user1);
        assertFalse(isValid);
        
        vm.stopPrank();
    }

    function test_Revoke_NotIssuer() public {
        vm.prank(user1);
        bytes32 recordId = axiom.register{value: BASE_FEE}(contentHash1, "");
        
        vm.prank(user2);
        vm.expectRevert();
        axiom.revoke(recordId, "Not my content");
    }

    function test_Revoke_AlreadyRevoked() public {
        vm.startPrank(user1);
        bytes32 recordId = axiom.register{value: BASE_FEE}(contentHash1, "");
        axiom.revoke(recordId, "First revoke");
        
        vm.expectRevert();
        axiom.revoke(recordId, "Second revoke");
        vm.stopPrank();
    }

    // ============ Identity Tests ============

    function test_RegisterIdentity() public {
        vm.startPrank(user1);
        
        axiom.registerIdentity("Reuters News", "ipfs://proof123");
        
        AxiomTypes.IdentityInfo memory info = axiom.resolveIdentity(user1);
        assertEq(info.name, "Reuters News");
        assertFalse(info.isVerified);
        
        vm.stopPrank();
    }

    function test_VerifyIdentity() public {
        vm.prank(user1);
        axiom.registerIdentity("CNN", "ipfs://proof");
        
        vm.prank(operator);
        axiom.verifyIdentity(user1);
        
        assertTrue(axiom.isIdentityVerified(user1));
    }

    function test_ResolveByName() public {
        vm.prank(user1);
        axiom.registerIdentity("BBC News", "ipfs://proof");
        
        address resolved = axiom.resolveByName("BBC News");
        assertEq(resolved, user1);
    }

    function test_Identity_DuplicateName() public {
        vm.prank(user1);
        axiom.registerIdentity("UniqueNews", "");
        
        vm.prank(user2);
        vm.expectRevert();
        axiom.registerIdentity("UniqueNews", "");
    }

    // ============ Treasury Tests ============

    function test_SetBaseFee() public {
        uint256 newFee = 0.001 ether;
        
        vm.prank(admin);
        axiom.setBaseFee(newFee);
        
        assertEq(axiom.getBaseFee(), newFee);
    }

    function test_EnterpriseRate() public {
        vm.startPrank(admin);
        
        // Grant enterprise status
        axiom.grantEnterpriseStatus(enterprise);
        assertTrue(axiom.isEnterpriseUser(enterprise));
        
        // Set custom rate
        axiom.setEnterpriseRate(enterprise, 0.00001 ether);
        assertEq(axiom.getFee(enterprise), 0.00001 ether);
        
        vm.stopPrank();
    }

    function test_Withdraw() public {
        // First accumulate some fees
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "");
        
        uint256 contractBalance = address(axiom).balance;
        assertTrue(contractBalance >= BASE_FEE);
        
        uint256 treasuryBalanceBefore = treasury.balance;
        
        vm.prank(admin);
        axiom.withdraw(treasury, contractBalance);
        
        assertEq(treasury.balance - treasuryBalanceBefore, contractBalance);
    }

    // ============ Access Control Tests ============

    function test_BanAddress() public {
        vm.prank(operator);
        axiom.banAddress(user1, "Spam");
        
        assertTrue(axiom.isBanned(user1));
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.register{value: BASE_FEE}(contentHash1, "");
    }

    function test_UnbanAddress() public {
        vm.startPrank(operator);
        axiom.banAddress(user1, "Spam");
        axiom.unbanAddress(user1);
        vm.stopPrank();
        
        assertFalse(axiom.isBanned(user1));
        
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "");
    }

    function test_DisputeContent() public {
        vm.prank(user1);
        bytes32 recordId = axiom.register{value: BASE_FEE}(contentHash1, "");
        
        vm.prank(operator);
        axiom.disputeContent(recordId, "Possible deepfake");
        
        AxiomTypes.AxiomRecord memory record = axiom.getRecord(recordId);
        assertEq(uint8(record.status), uint8(AxiomTypes.ContentStatus.DISPUTED));
    }

    function test_Pause() public {
        vm.prank(admin);
        axiom.pause();
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.register{value: BASE_FEE}(contentHash1, "");
        
        vm.prank(admin);
        axiom.unpause();
        
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, ""); // Should work now
    }

    // ============ Rate Limit Tests ============

    function test_RateLimit() public {
        vm.startPrank(user1);
        
        // Register 10 times (max allowed)
        for (uint256 i = 0; i < 10; i++) {
            bytes32 hash = keccak256(abi.encodePacked("content", i));
            axiom.register{value: BASE_FEE}(hash, "");
        }
        
        // 11th should fail
        bytes32 limitedHash = keccak256("content10");
        vm.expectRevert();
        axiom.register{value: BASE_FEE}(limitedHash, "");
        
        vm.stopPrank();
    }

    function test_EnterpriseBypassesRateLimit() public {
        vm.prank(admin);
        axiom.grantEnterpriseStatus(enterprise);
        
        vm.startPrank(enterprise);
        
        // Should be able to register more than 10 times
        for (uint256 i = 0; i < 15; i++) {
            bytes32 hash = keccak256(abi.encodePacked("enterprise", i));
            axiom.register{value: BASE_FEE}(hash, "");
        }
        
        vm.stopPrank();
        
        assertEq(axiom.getTotalRecords(), 15);
    }

    // ============ Additional Coverage Tests ============

    function test_UpdateIdentity() public {
        // First register identity
        vm.prank(user1);
        axiom.registerIdentity("OldName", "ipfs://old");
        
        // Update identity
        vm.prank(user1);
        axiom.updateIdentity("NewName", "ipfs://new");
        
        AxiomTypes.IdentityInfo memory info = axiom.resolveIdentity(user1);
        assertEq(info.name, "NewName");
        assertEq(info.proofURI, "ipfs://new");
        
        // Old name should be freed
        assertEq(axiom.resolveByName("OldName"), address(0));
        assertEq(axiom.resolveByName("NewName"), user1);
    }

    function test_UpdateIdentity_NotRegistered() public {
        vm.prank(user1);
        vm.expectRevert();
        axiom.updateIdentity("Name", "");
    }

    function test_UpdateIdentity_NameTaken() public {
        vm.prank(user1);
        axiom.registerIdentity("TakenName", "");
        
        vm.prank(user2);
        axiom.registerIdentity("OtherName", "");
        
        // Try to update to taken name
        vm.prank(user2);
        vm.expectRevert("Name already taken");
        axiom.updateIdentity("TakenName", "");
    }

    function test_RevokeVerification() public {
        // Register identity
        vm.prank(user1);
        axiom.registerIdentity("Verified", "");
        
        // Verify first
        vm.prank(operator);
        axiom.verifyIdentity(user1);
        assertTrue(axiom.isIdentityVerified(user1));
        
        // Revoke verification
        vm.prank(operator);
        axiom.revokeVerification(user1);
        assertFalse(axiom.isIdentityVerified(user1));
    }

    function test_RevokeVerification_NotRegistered() public {
        vm.prank(operator);
        vm.expectRevert();
        axiom.revokeVerification(user1);
    }

    function test_VerifyIdentity_NotRegistered() public {
        vm.prank(operator);
        vm.expectRevert();
        axiom.verifyIdentity(user1);
    }

    function test_RevokeEnterpriseStatus() public {
        // Grant enterprise first
        vm.prank(admin);
        axiom.grantEnterpriseStatus(enterprise);
        assertTrue(axiom.isEnterpriseUser(enterprise));
        
        // Revoke enterprise
        vm.prank(admin);
        axiom.revokeEnterpriseStatus(enterprise);
        assertFalse(axiom.isEnterpriseUser(enterprise));
    }

    function test_SetTreasuryWallet() public {
        address newTreasury = address(100);
        
        vm.prank(admin);
        axiom.setTreasuryWallet(newTreasury);
        
        // Verify by using the getFee which uses storage
        // (indirect verification since treasuryWallet is storage)
    }

    function test_SetTreasuryWallet_InvalidAddress() public {
        vm.prank(admin);
        vm.expectRevert("Invalid address");
        axiom.setTreasuryWallet(address(0));
    }

    function test_GetTotalFeesCollected() public {
        // Initially 0
        assertEq(axiom.getTotalFeesCollected(), 0);
        
        // Register and check fees collected
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "");
        
        assertEq(axiom.getTotalFeesCollected(), BASE_FEE);
    }

    function test_SetRateLimit() public {
        vm.prank(admin);
        axiom.setRateLimit(120, 20); // 2 minutes, 20 actions
        
        // Verify by testing rate limit behavior
        vm.startPrank(user1);
        for (uint256 i = 0; i < 15; i++) {
            bytes32 hash = keccak256(abi.encodePacked("ratelimit", i));
            axiom.register{value: BASE_FEE}(hash, "");
        }
        vm.stopPrank();
        
        // Should have succeeded since limit is now 20
        assertEq(axiom.getTotalRecords(), 15);
    }

    function test_SetMaxBatchSize() public {
        // Set max batch to 5
        vm.prank(admin);
        axiom.setMaxBatchSize(5);
        
        // Try batch of 6 - should fail
        bytes32[] memory hashes = new bytes32[](6);
        string[] memory uris = new string[](6);
        for (uint256 i = 0; i < 6; i++) {
            hashes[i] = keccak256(abi.encodePacked("batch", i));
            uris[i] = "";
        }
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.batchRegister{value: BASE_FEE * 6}(hashes, uris);
    }

    function test_BatchRegister_ExceedsMaxBatchSize() public {
        // Default maxBatchSize is 100, create 101
        bytes32[] memory hashes = new bytes32[](101);
        string[] memory uris = new string[](101);
        for (uint256 i = 0; i < 101; i++) {
            hashes[i] = keccak256(abi.encodePacked("oversized", i));
            uris[i] = "";
        }
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.batchRegister{value: BASE_FEE * 101}(hashes, uris);
    }

    function test_BatchRegister_SkipsDuplicates() public {
        // First register one hash
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "");
        
        // Try batch with that hash included
        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = contentHash1; // Already exists
        hashes[1] = contentHash2;
        hashes[2] = contentHash3;
        
        string[] memory uris = new string[](3);
        uris[0] = ""; uris[1] = ""; uris[2] = "";
        
        vm.prank(user1);
        bytes32[] memory recordIds = axiom.batchRegister{value: BASE_FEE * 3}(hashes, uris);
        
        // First should be skipped (bytes32(0)), others created
        assertEq(recordIds[0], bytes32(0));
        assertTrue(recordIds[1] != bytes32(0));
        assertTrue(recordIds[2] != bytes32(0));
        
        // Total should be 3 (1 from first + 2 from batch)
        assertEq(axiom.getTotalRecords(), 3);
    }

    function test_BatchRegister_InsufficientFee() public {
        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = contentHash1;
        hashes[1] = contentHash2;
        hashes[2] = contentHash3;
        
        string[] memory uris = new string[](3);
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.batchRegister{value: BASE_FEE}(hashes, uris); // Only 1 fee for 3 items
    }

    function test_GetRecordsByIssuer() public {
        vm.startPrank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "");
        axiom.register{value: BASE_FEE}(contentHash2, "");
        axiom.register{value: BASE_FEE}(contentHash3, "");
        vm.stopPrank();
        
        bytes32[] memory records = axiom.getRecordsByIssuer(user1);
        assertEq(records.length, 3);
    }

    function test_GetRecord_NotFound() public {
        bytes32 fakeRecordId = keccak256("nonexistent");
        
        vm.expectRevert();
        axiom.getRecord(fakeRecordId);
    }

    function test_Revoke_RecordNotFound() public {
        bytes32 fakeRecordId = keccak256("nonexistent");
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.revoke(fakeRecordId, "reason");
    }

    function test_DisputeContent_RecordNotFound() public {
        bytes32 fakeRecordId = keccak256("nonexistent");
        
        vm.prank(operator);
        vm.expectRevert();
        axiom.disputeContent(fakeRecordId, "reason");
    }

    function test_Withdraw_InvalidRecipient() public {
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "");
        
        vm.prank(admin);
        vm.expectRevert("Invalid recipient");
        axiom.withdraw(address(0), BASE_FEE);
    }

    function test_Withdraw_InsufficientBalance() public {
        vm.prank(admin);
        vm.expectRevert("Insufficient balance");
        axiom.withdraw(treasury, 1 ether);
    }

    function test_ReceiveEth() public {
        // Direct ETH transfer
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        (bool success,) = address(axiom).call{value: 0.1 ether}("");
        assertTrue(success);
        assertEq(address(axiom).balance, 0.1 ether);
    }

    function test_Upgrade() public {
        // Deploy new implementation
        AxiomRouter newImpl = new AxiomRouter();
        
        // Upgrade (must be UPGRADER_ROLE)
        vm.prank(admin);
        axiom.upgradeToAndCall(address(newImpl), "");
        
        // Verify still works
        assertEq(axiom.VERSION(), "1.0.0");
    }

    function test_Upgrade_Unauthorized() public {
        AxiomRouter newImpl = new AxiomRouter();
        
        // Non-upgrader cannot upgrade
        vm.prank(user1);
        vm.expectRevert();
        axiom.upgradeToAndCall(address(newImpl), "");
    }

    function test_RegisterIdentity_AlreadyExists() public {
        vm.prank(user1);
        axiom.registerIdentity("Name1", "");
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.registerIdentity("Name2", "");
    }

    function test_RegisterIdentity_WhenBanned() public {
        vm.prank(operator);
        axiom.banAddress(user1, "banned");
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.registerIdentity("Name", "");
    }

    function test_UpdateIdentity_WhenBanned() public {
        vm.prank(user1);
        axiom.registerIdentity("Name", "");
        
        vm.prank(operator);
        axiom.banAddress(user1, "banned");
        
        vm.prank(user1);
        vm.expectRevert();
        axiom.updateIdentity("NewName", "");
    }

    function test_RateLimitReset_AfterWindow() public {
        vm.startPrank(user1);
        
        // Register up to limit
        for (uint256 i = 0; i < 10; i++) {
            bytes32 hash = keccak256(abi.encodePacked("window1", i));
            axiom.register{value: BASE_FEE}(hash, "");
        }
        vm.stopPrank();
        
        // Warp time beyond rate limit window (60 seconds default)
        vm.warp(block.timestamp + 61);
        
        // Should be able to register again
        vm.prank(user1);
        bytes32 hash = keccak256("window2_0");
        axiom.register{value: BASE_FEE}(hash, "");
        
        assertEq(axiom.getTotalRecords(), 11);
    }

    function test_GetFee_Enterprise() public {
        vm.startPrank(admin);
        axiom.grantEnterpriseStatus(enterprise);
        axiom.setEnterpriseRate(enterprise, 0.00005 ether);
        vm.stopPrank();
        
        assertEq(axiom.getFee(enterprise), 0.00005 ether);
    }

    function test_GetFee_Regular() public view {
        assertEq(axiom.getFee(user1), BASE_FEE);
    }

    function test_EnterpriseWithoutCustomRate() public {
        // Grant enterprise but no custom rate
        vm.prank(admin);
        axiom.grantEnterpriseStatus(enterprise);
        
        // Should use base fee since no custom rate set
        assertEq(axiom.getFee(enterprise), BASE_FEE);
    }

    // ============ Fuzz Tests ============

    function testFuzz_Register(bytes32 hash, string calldata uri) public {
        vm.assume(hash != bytes32(0));
        
        vm.prank(user1);
        bytes32 recordId = axiom.register{value: BASE_FEE}(hash, uri);
        
        AxiomTypes.AxiomRecord memory record = axiom.getRecord(recordId);
        assertEq(record.contentHash, hash);
        assertEq(record.metadataURI, uri);
    }

    function testFuzz_Verify(bytes32 hash, address issuer) public {
        vm.assume(issuer != address(0));
        vm.deal(issuer, 1 ether);
        
        vm.prank(issuer);
        axiom.register{value: BASE_FEE}(hash, "");
        
        (bool isValid,) = axiom.verify(hash, issuer);
        assertTrue(isValid);
    }

    function testFuzz_BatchRegister(uint8 count) public {
        vm.assume(count > 0 && count <= 50);
        
        bytes32[] memory hashes = new bytes32[](count);
        string[] memory uris = new string[](count);
        
        for (uint256 i = 0; i < count; i++) {
            hashes[i] = keccak256(abi.encodePacked("fuzz", i));
            uris[i] = "";
        }
        
        uint256 totalFee = BASE_FEE * count;
        vm.deal(user1, totalFee);
        
        vm.prank(user1);
        bytes32[] memory recordIds = axiom.batchRegister{value: totalFee}(hashes, uris);
        
        assertEq(recordIds.length, count);
    }

    // ============ Transfer Failure Tests ============

    function test_Register_RefundFails() public {
        // Deploy a contract that rejects ETH
        EthRejecter rejecter = new EthRejecter(address(axiom));
        vm.deal(address(rejecter), 10 ether);
        
        // Register with excess - refund should fail
        bytes32 hash = keccak256("rejecter_test");
        
        vm.prank(address(rejecter));
        vm.expectRevert("Refund failed");
        rejecter.registerWithExcess{value: 1 ether}(hash);
    }

    function test_BatchRegister_RefundFails() public {
        // Deploy a contract that rejects ETH
        EthRejecter rejecter = new EthRejecter(address(axiom));
        vm.deal(address(rejecter), 10 ether);
        
        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = keccak256("batch1");
        hashes[1] = keccak256("batch2");
        
        string[] memory uris = new string[](2);
        uris[0] = "";
        uris[1] = "";
        
        // Send excess - refund should fail
        vm.prank(address(rejecter));
        vm.expectRevert("Refund failed");
        rejecter.batchRegisterWithExcess{value: 1 ether}(hashes, uris);
    }

    function test_Withdraw_TransferFails() public {
        // First accumulate fees
        vm.prank(user1);
        axiom.register{value: BASE_FEE}(contentHash1, "");
        
        // Deploy contract that rejects ETH
        EthRejecter rejecter = new EthRejecter(address(axiom));
        
        // Try to withdraw to this contract
        vm.prank(admin);
        vm.expectRevert("Transfer failed");
        axiom.withdraw(address(rejecter), BASE_FEE);
    }
}

/**
 * @title EthRejecter
 * @notice Contract that rejects ETH transfers (for testing transfer failure branches)
 */
contract EthRejecter {
    AxiomRouter public axiom;
    
    constructor(address _axiom) {
        axiom = AxiomRouter(payable(_axiom));
    }
    
    function registerWithExcess(bytes32 hash) external payable {
        axiom.register{value: msg.value}(hash, "");
    }
    
    function batchRegisterWithExcess(bytes32[] calldata hashes, string[] calldata uris) external payable {
        axiom.batchRegister{value: msg.value}(hashes, uris);
    }
    
    // Reject all ETH transfers
    receive() external payable {
        revert("EthRejecter: no ETH accepted");
    }
}
