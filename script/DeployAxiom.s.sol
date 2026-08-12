// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AxiomRouter} from "../src/AxiomRouter.sol";

/**
 * @title DeployAxiom
 * @notice Router-only bootstrap retained for compatibility.
 * @dev This does not install facets and therefore is not a complete protocol
 *      deployment. Use DeployPhase4 for a fresh usable deployment.
 */
contract DeployAxiom is Script {
    function run() public returns (address proxy, address implementation) {
        // Resolve the actual signer selected by Foundry before using it as
        // the initial admin. `msg.sender` before startBroadcast() is only the
        // script caller/default sender, not necessarily the selected account.
        vm.startBroadcast();
        (, address broadcaster,) = vm.readCallers();
        address admin = vm.envOr("ADMIN_ADDRESS", broadcaster);
        if (admin != broadcaster) revert AdminSignerMismatch(admin, broadcaster);
        address treasury = vm.envOr("TREASURY_ADDRESS", admin);

        console2.log("Deploying Axiom Router bootstrap only...");
        console2.log("Admin:", admin);
        console2.log("Treasury:", treasury);

        // Deploy implementation
        AxiomRouter axiomImpl = new AxiomRouter();
        console2.log("Implementation deployed at:", address(axiomImpl));

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(AxiomRouter.initialize.selector, admin, treasury);

        // Deploy proxy
        ERC1967Proxy axiomProxy = new ERC1967Proxy(address(axiomImpl), initData);
        console2.log("Proxy deployed at:", address(axiomProxy));

        vm.stopBroadcast();

        // Verify deployment
        AxiomRouter axiom = AxiomRouter(payable(address(axiomProxy)));
        console2.log("Protocol Version:", axiom.VERSION());
        // Base Fee now requires facet to be registered
        // console2.log("Base Fee:", axiom.getBaseFee());
        console2.log("Router bootstrap complete; no facets are installed.");

        return (address(axiomProxy), address(axiomImpl));
    }

    error AdminSignerMismatch(address configuredAdmin, address broadcastSigner);
}

/**
 * @title DeployAxiomLocal
 * @notice Local router-only bootstrap with test values.
 * @dev Use DeployPhase4 when the local environment needs the full protocol.
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
        bytes memory initData = abi.encodeWithSelector(AxiomRouter.initialize.selector, deployer, deployer);

        ERC1967Proxy axiomProxy = new ERC1967Proxy(address(axiomImpl), initData);

        vm.stopBroadcast();

        console2.log("Proxy:", address(axiomProxy));
        console2.log("Implementation:", address(axiomImpl));

        return address(axiomProxy);
    }
}
