// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import { JustanAccount } from "../src/JustanAccount.sol";
import { JustanAccountFactory } from "../src/JustanAccountFactory.sol";
import { HelperConfig } from "./HelperConfig.s.sol";
import { Script, console2 } from "forge-std/Script.sol";
import { SafeSingletonDeployer } from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

contract DeployJustanAccount is Script {

    address constant EXPECTED_IMPLEMENTATION = 0xbC88Ca86B15CE0136C5A92A979B86c6DdB632112;
    address constant EXPECTED_FACTORY = 0xd4a5E8c1E9ca9F92446944A831bc5C71Fb379819;

    bytes32 constant IMPLEMENTATION_SALT = 0x0000000000000000000000000000000000000000000000000000000000000000;
    bytes32 constant FACTORY_SALT = 0x0000000000000000000000000000000000000000000000000000000000000000;

    function run() external returns (JustanAccount, JustanAccountFactory, HelperConfig.NetworkConfig memory) {
        HelperConfig helperConfig = new HelperConfig();
        HelperConfig.NetworkConfig memory config = helperConfig.getConfig();

        console2.log("Deploying on chain ID", block.chainid);

        address implementation;
        address factory;

        if (block.chainid == 31_337) {
            vm.startBroadcast();
            implementation = address(new JustanAccount(config.entryPointAddress));
            factory = address(new JustanAccountFactory(implementation));
            vm.stopBroadcast();
        } else {
            implementation = SafeSingletonDeployer.broadcastDeploy({
                creationCode: type(JustanAccount).creationCode,
                args: abi.encode(config.entryPointAddress),
                salt: IMPLEMENTATION_SALT
            });

            console2.log("implementation", implementation);
            assert(implementation == EXPECTED_IMPLEMENTATION);

            factory = SafeSingletonDeployer.broadcastDeploy({
                creationCode: type(JustanAccountFactory).creationCode,
                args: abi.encode(implementation),
                salt: FACTORY_SALT
            });

            console2.log("factory", factory);
            assert(factory == EXPECTED_FACTORY);
        }

        return (JustanAccount(payable(implementation)), JustanAccountFactory(factory), config);
    }

}
