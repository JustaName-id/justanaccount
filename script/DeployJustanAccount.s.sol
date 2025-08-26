// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import { JustanAccount } from "../src/JustanAccount.sol";
import { JustanAccountFactory } from "../src/JustanAccountFactory.sol";
import { HelperConfig } from "./HelperConfig.s.sol";
import { Script } from "forge-std/Script.sol";

contract DeployJustanAccount is Script {

    function run() external returns (JustanAccount, JustanAccountFactory, HelperConfig.NetworkConfig memory) {
        HelperConfig helperConfig = new HelperConfig();
        HelperConfig.NetworkConfig memory config = helperConfig.getConfig();

        vm.startBroadcast();
        JustanAccount account = new JustanAccount{ salt: 0 }(config.entryPointAddress);
        JustanAccountFactory factory = new JustanAccountFactory{ salt: 0 }(address(account));
        vm.stopBroadcast();

        return (account, factory, config);
    }

}
