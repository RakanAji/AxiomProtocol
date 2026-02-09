// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AxiomRouter.sol";

// --- MOCK CONTRACTS ---

/**
 * @title HeavyWallet
 * @notice Wallet ini mensimulasikan Gnosis Safe atau Smart Wallet kompleks
 * yang membutuhkan gas lebih dari 2300 saat menerima ETH.
 */
contract HeavyWallet {
    // Fungsi receive() ini sengaja "boros gas"
    receive() external payable {
        // Menulis ke storage memakan minimal 5000 gas (Cold Access)
        // .transfer() hanya mengirim 2300 gas -> Pasti GAGAL (Out of Gas)
        assembly {
            sstore(0, 1)
        }
    }
}

// --- AUDIT TEST SUITE ---

contract RealAuditTest is Test {
    AxiomRouter router;
    HeavyWallet heavyWallet;
    address admin = makeAddr("admin");

    function setUp() public {
        // 1. Setup Admin
        vm.startPrank(admin);
        
        // 2. Deploy Router
        router = new AxiomRouter();
        router.initialize(admin, address(0)); 
        
        vm.stopPrank();
        
        // 3. Deploy Wallet Penerima yang "Berat"
        heavyWallet = new HeavyWallet();
        
        // 4. Beri modal ke Router (Simulasi uang protokol)
        vm.deal(address(router), 10 ether);
    }

    /**
     * @notice POC untuk Finding #2: Withdraw menggunakan .transfer()
     * @dev Membuktikan bahwa dana akan terkunci jika penerima adalah Smart Contract.
     */
    function testFinding_WithdrawTrap() public {
        vm.startPrank(admin);
        
        console.log("Saldo Awal HeavyWallet:", address(heavyWallet).balance);
        console.log("Mencoba withdraw 1 ETH ke HeavyWallet...");
        
        // EKSPEKTASI: Transaksi harus REVERT (Gagal)
        // Kita gunakan vm.expectRevert() untuk mengkonfirmasi bahwa bug itu ADA.
        // Jika test ini PASS, berarti bug-nya terkonfirmasi (transaksi memang gagal).
        vm.expectRevert(); 
        
        router.withdraw(address(heavyWallet), 1 ether);
        
        console.log("Konfirmasi: Withdraw GAGAL karena Out of Gas limit (2300).");
        
        vm.stopPrank();
    }
}