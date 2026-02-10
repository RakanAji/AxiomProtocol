// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/core/AxiomLicenseNFT.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// 1. MOCK: Penerima Royalti yang "Rusak" (Menolak ETH)
contract BrokenRecipient {
    // Tidak ada receive() atau fallback(), jadi transfer ETH pasti gagal
    // Atau kita eksplisit revert:
    receive() external payable {
        revert("Saya menolak uang!");
    }
}

contract LicenseAuditTest is Test {
    AxiomLicenseNFT licenseNFT;
    address admin = makeAddr("admin");
    address creator = makeAddr("creator"); // Pembuat Lisensi
    address buyer = makeAddr("buyer");     // Pembeli
    BrokenRecipient poisonWallet;          // Penerima Royalti Bermasalah

    function setUp() public {
        vm.startPrank(admin);
        
        // Deploy Proxy & Logic
        AxiomLicenseNFT implementation = new AxiomLicenseNFT();
        // Encode initialize(admin, treasury, registry)
        bytes memory initData = abi.encodeWithSelector(
            AxiomLicenseNFT.initialize.selector, 
            admin, 
            makeAddr("treasury"), 
            makeAddr("registry")
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        licenseNFT = AxiomLicenseNFT(payable(address(proxy)));
        
        vm.stopPrank();

        // Deploy Poison Wallet
        poisonWallet = new BrokenRecipient();
        vm.deal(buyer, 100 ether); // Modal pembeli
    }

    /**
     * @notice POC untuk Finding [H-03]: Royalty Push Pattern DoS
     * @dev Membuktikan bahwa satu penerima royalti yang error bisa membatalkan seluruh penjualan.
     */
    function testFinding_RoyaltyPoisoning() public {
        // 1. Creator membuat Lisensi
        vm.startPrank(creator);
        uint256 licenseId = licenseNFT.createLicense(
            keccak256("lagu-baru"), 
            AxiomTypesV2.LicenseType.COMMERCIAL_SINGLE, 
            1 ether,    // Harga 1 ETH
            address(0), // Bayar pakai ETH
            1000,       // Royalti 10%
            0, false, false, ""
        );

        // 2. Creator mengatur Royalti Split
        // Dia mengajak teman, tapi salah satunya adalah Poison Wallet
        address[] memory recipients = new address[](2);
        recipients[0] = makeAddr("friend"); // Teman normal
        recipients[1] = address(poisonWallet); // Teman yang walletnya rusak
        
        uint16[] memory shares = new uint16[](2);
        shares[0] = 5000; // 50%
        shares[1] = 5000; // 50%
        
        licenseNFT.setRoyaltySplit(keccak256("lagu-baru"), recipients, shares);
        vm.stopPrank();

        // 3. Buyer mencoba membeli lisensi
        vm.startPrank(buyer);
        console.log("Buyer mencoba membeli lisensi seharga 1 ETH...");
        
        // EKSPEKTASI: GAGAL (Revert) karena BrokenRecipient menolak royalti
        // Padahal buyer sudah bayar benar, dan creator ingin jualan.
        vm.expectRevert("Royalty transfer failed"); 
        
        licenseNFT.purchaseLicense{value: 1 ether}(licenseId, 0);
        
        console.log("Konfirmasi: Pembelian GAGAL total karena satu penerima royalti bermasalah.");
        vm.stopPrank();
    }
}