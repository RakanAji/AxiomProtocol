// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AxiomRouter.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract IdentityAuditTest is Test {
    AxiomRouter router;
    address user = makeAddr("user1");
    address admin = makeAddr("admin");

    function setUp() public {
        vm.startPrank(admin);
        
        // 1. Setup Proxy & Logic (Sama seperti sebelumnya)
        AxiomRouter implementation = new AxiomRouter();
        bytes memory initData = abi.encodeWithSelector(AxiomRouter.initialize.selector, admin, address(0));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        router = AxiomRouter(payable(address(proxy)));
        
        vm.stopPrank();
    }

    /**
     * @notice POC untuk Finding [M-02]: Incomplete Identity Update
     * @dev Membuktikan bahwa updateIdentity gagal mengupdate reverse-lookup mapping.
     */
    function testFinding_IdentityInconsistency() public {
        vm.startPrank(user);
        
        // 1. User Register nama "AxiomUser"
        console.log("1. User register sebagai 'AxiomUser'");
        router.registerIdentity("AxiomUser", "ipfs://proof1");
        
        // Verifikasi Awal
        assertEq(router.resolveByName("AxiomUser"), user);
        
        // 2. User Ganti Nama jadi "SuperUser"
        console.log("2. User update nama jadi 'SuperUser'");
        router.updateIdentity("SuperUser", "ipfs://proof2");
        
        // 3. CEK KONSISTENSI DATA (Bug Check)
        address lookupOld = router.resolveByName("AxiomUser");
        address lookupNew = router.resolveByName("SuperUser");
        
        console.log("Lookup Nama Lama ('AxiomUser'):", lookupOld);
        console.log("Lookup Nama Baru ('SuperUser'):", lookupNew);
        
        // EKSPEKTASI AUDITOR:
        // Nama Lama harusnya sudah dilepas (address(0)), tapi BUG membuatnya masih nempel.
        assertEq(lookupOld, user, "BUG: Nama lama tidak terlepas!");
        
        // Nama Baru harusnya terdaftar (user), tapi BUG membuatnya tidak ditemukan.
        assertEq(lookupNew, address(0), "BUG: Nama baru tidak terdaftar di lookup!");
        
        console.log("Konfirmasi: Data Identitas TIDAK KONSISTEN.");
        
        vm.stopPrank();
    }
}