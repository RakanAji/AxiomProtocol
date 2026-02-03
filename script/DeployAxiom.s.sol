// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AxiomRouter} from "../src/AxiomRouter.sol";

/**
 * @title DeployAxiom
 * @notice Deployment script for Axiom Protocol
 */
contract DeployAxiom is Script {
    function run() public returns (address proxy, address implementation) {
        // Get deployment config from environment
        address admin = vm.envOr("ADMIN_ADDRESS", msg.sender);
        address treasury = vm.envOr("TREASURY_ADDRESS", msg.sender);
        
        console2.log("Deploying Axiom Protocol...");
        console2.log("Admin:", admin);
        console2.log("Treasury:", treasury);

        vm.startBroadcast();

        // Deploy implementation
        AxiomRouter axiomImpl = new AxiomRouter();
        console2.log("Implementation deployed at:", address(axiomImpl));

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            AxiomRouter.initialize.selector,
            admin,
            treasury
        );

        // Deploy proxy
        ERC1967Proxy axiomProxy = new ERC1967Proxy(
            address(axiomImpl),
            initData
        );
        console2.log("Proxy deployed at:", address(axiomProxy));

        vm.stopBroadcast();

        // Verify deployment
        AxiomRouter axiom = AxiomRouter(payable(address(axiomProxy)));
        console2.log("Protocol Version:", axiom.VERSION());
        console2.log("Base Fee:", axiom.getBaseFee());
        console2.log("Deployment complete!");

        return (address(axiomProxy), address(axiomImpl));
    }
}

/**
 * @title DeployAxiomLocal
 * @notice Local/Testnet deployment with test values
 */
contract DeployAxiomLocal is Script {
    function run() public returns (address) {
        address deployer = vm.addr(vm.envUint("PRIVATE_KEY"));
        
        console2.log("Deploying to local/testnet...");
        console2.log("Deployer:", deployer);

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        // Deploy implementation
        AxiomRouter axiomImpl = new AxiomRouter();

        // Deploy proxy with deployer as admin and treasury
        bytes memory initData = abi.encodeWithSelector(
            AxiomRouter.initialize.selector,
            deployer,
            deployer
        );

        ERC1967Proxy axiomProxy = new ERC1967Proxy(
            address(axiomImpl),
            initData
        );

        vm.stopBroadcast();

        console2.log("Proxy:", address(axiomProxy));
        console2.log("Implementation:", address(axiomImpl));

        return address(axiomProxy);
    }
}
