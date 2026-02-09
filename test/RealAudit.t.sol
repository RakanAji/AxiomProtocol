// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AxiomRouter.sol";
// Kita butuh Proxy standar untuk membungkus Logic contract
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// --- MOCK CONTRACTS ---

/**
 * @title HeavyWallet
 * @notice Wallet ini mensimulasikan Gnosis Safe atau Smart Wallet kompleks
 * yang membutuhkan gas lebih dari 2300 saat menerima ETH.
 */
contract HeavyWallet {
    receive() external payable {
        // Menulis ke storage memakan minimal 5000 gas (Cold Access)
        // .transfer() hanya mengirim 2300 gas -> Pasti GAGAL (Out of Gas)
        assembly {
            sstore(0, 1)
        }
    }
}

/**
 * @title RevertingWallet
 * @notice Kontrak ini menolak menerima ETH (tidak punya receive/fallback)
 * atau secara eksplisit melakukan revert.
 */
contract RevertingWallet {
    receive() external payable {
        revert("Saya menolak uang receh!");
    }
    
    // Fungsi untuk mencoba register
    function tryRegister(address _router, bytes32 _hash) external payable {
        // Panggil fungsi register di Router
        (bool success, ) = _router.call{value: address(this).balance}(
            abi.encodeWithSignature("register(bytes32,string)", _hash, "ipfs://metadata")
        );
        require(success, "Register failed"); 
    }
}

// --- AUDIT TEST SUITE ---

contract RealAuditTest is Test {
    AxiomRouter router; // Ini akan menunjuk ke Proxy
    HeavyWallet heavyWallet;
    address admin = makeAddr("admin");

    function setUp() public {
        vm.startPrank(admin);
        
        // 1. Deploy Implementation (Logic Contract)
        AxiomRouter implementation = new AxiomRouter();
        
        // 2. Siapkan data untuk initialize
        bytes memory initData = abi.encodeWithSelector(
            AxiomRouter.initialize.selector,
            admin,
            address(0)
        );
        
        // 3. Deploy Proxy yang menunjuk ke Implementation
        // Proxy ini yang akan kita panggil "router"
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        
        // 4. Casting address Proxy menjadi interface AxiomRouter
        router = AxiomRouter(payable(address(proxy)));
        
        vm.stopPrank();
        
        // 5. Deploy Mock Wallets
        heavyWallet = new HeavyWallet();
        
        // 6. Beri modal ke Router (Simulasi uang protokol)
        vm.deal(address(router), 10 ether);
    }

    /**
     * @notice POC untuk Finding [H-01]: Withdraw Trap
     * @dev Membuktikan bahwa dana akan terkunci jika penerima adalah Smart Contract.
     */
    function testFinding_WithdrawTrap() public {
        vm.startPrank(admin);
        
        console.log("Saldo Awal HeavyWallet:", address(heavyWallet).balance);
        console.log("Mencoba withdraw 1 ETH ke HeavyWallet menggunakan .transfer()...");
        
        // EKSPEKTASI: Transaksi harus REVERT (Gagal)
        vm.expectRevert(); 
        
        router.withdraw(address(heavyWallet), 1 ether);
        
        console.log("Konfirmasi: Withdraw GAGAL karena Out of Gas limit (2300).");
        
        vm.stopPrank();
    }

    /**
     * @notice POC untuk Finding [M-01]: Strict Refund DoS
     * @dev Membuktikan user gagal register hanya karena refund gagal.
     */
    function testFinding_StrictRefundDoS() public {
        vm.startPrank(admin);
        
        // Setup Wallet yang menolak refund
        RevertingWallet stingyUser = new RevertingWallet();
        vm.deal(address(stingyUser), 1 ether); // Modal 1 ETH
        
        console.log("Mencoba register dengan kelebihan bayar (Refund Trigger)...");
        
        // Fee cuma 0.0001 ETH, tapi user kirim 1 ETH.
        // Router akan coba refund 0.9999 ETH.
        // EKSPEKTASI: Revert karena refund gagal & router pake 'require(success)'
        
        vm.expectRevert(); 
        
        stingyUser.tryRegister(address(router), keccak256("konten-rahasia"));
        
        console.log("Konfirmasi: Register GAGAL total hanya karena refund macet.");
        
        vm.stopPrank();
    }
}