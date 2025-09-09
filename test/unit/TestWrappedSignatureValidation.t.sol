// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@account-abstraction/core/Helpers.sol";

import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { Test, Vm, console } from "forge-std/Test.sol";

import { DeployJustanAccount } from "../../script/DeployJustanAccount.s.sol";
import { HelperConfig } from "../../script/HelperConfig.s.sol";
import { CodeConstants } from "../../script/HelperConfig.s.sol";
import { PreparePackedUserOp } from "../../script/PreparePackedUserOp.s.sol";
import { JustanAccount } from "../../src/JustanAccount.sol";
import { JustanAccountFactory } from "../../src/JustanAccountFactory.sol";

/**
 * @title TestWrappedSignatureValidation
 * @notice Unit tests for SignatureWrapper validation (multi-owner ECDSA signatures)
 * @dev Tests the wrapped signature validation path in JustanAccount._validateSignature()
 *      for signatures longer than 65 bytes that use the SignatureWrapper struct
 *      Uses factory to create account clones with initial owners
 */
contract TestWrappedSignatureValidation is Test, CodeConstants {

    JustanAccount public account;
    JustanAccountFactory public factory;
    HelperConfig.NetworkConfig public networkConfig;
    PreparePackedUserOp public preparePackedUserOp;

    uint256 public initialOwnerPk = TEST_ACCOUNT_PRIVATE_KEY;
    address public initialOwner = TEST_ACCOUNT_ADDRESS;

    bytes CALLDATA = abi.encodeWithSignature("execute(address,uint256,bytes)", address(0), 0, "");

    function setUp() public {
        DeployJustanAccount deployer = new DeployJustanAccount();
        (, factory, networkConfig) = deployer.run();

        preparePackedUserOp = new PreparePackedUserOp();

        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(initialOwner);

        account = factory.createAccount(owners, 0);
    }

    /*//////////////////////////////////////////////////////////////
                    WRAPPED SIGNATURE (SignatureWrapper) TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ShouldValidateWrappedSignature(uint256 newOwnerPk) public {
        vm.assume(newOwnerPk > 0 && newOwnerPk < SECP256K1_CURVE_ORDER);
        vm.assume(newOwnerPk != initialOwnerPk);

        address newOwner = vm.addr(newOwnerPk);

        vm.prank(initialOwner);
        account.addOwnerAddress(newOwner);

        (PackedUserOperation memory userOp, bytes32 userOpHash) = preparePackedUserOp.generateSignedUserOperation(
            CALLDATA, newOwner, newOwnerPk, networkConfig.entryPointAddress, false
        );

        JustanAccount.SignatureWrapper memory sigWrapper =
            JustanAccount.SignatureWrapper({ ownerIndex: 1, signatureData: userOp.signature });

        userOp.signature = abi.encode(sigWrapper);

        vm.prank(networkConfig.entryPointAddress);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, SIG_VALIDATION_SUCCESS);
    }

    function test_ShouldFailWrappedSignatureWithoutOwner(uint256 nonOwnerPk) public {
        vm.assume(nonOwnerPk > 0 && nonOwnerPk < SECP256K1_CURVE_ORDER);
        vm.assume(nonOwnerPk != initialOwnerPk);

        address nonOwner = vm.addr(nonOwnerPk);

        (PackedUserOperation memory userOp, bytes32 userOpHash) = preparePackedUserOp.generateSignedUserOperation(
            CALLDATA, nonOwner, nonOwnerPk, networkConfig.entryPointAddress, false
        );

        JustanAccount.SignatureWrapper memory sigWrapper =
            JustanAccount.SignatureWrapper({ ownerIndex: 0, signatureData: userOp.signature });

        userOp.signature = abi.encode(sigWrapper);

        vm.prank(networkConfig.entryPointAddress);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, SIG_VALIDATION_FAILED);
    }

    function test_ShouldFailWrappedSignatureWithWrongSigner(uint256 newOwnerPk, uint256 wrongSignerPk) public {
        vm.assume(newOwnerPk > 0 && newOwnerPk < SECP256K1_CURVE_ORDER);
        vm.assume(wrongSignerPk > 0 && wrongSignerPk < SECP256K1_CURVE_ORDER);
        vm.assume(newOwnerPk != initialOwnerPk);
        vm.assume(wrongSignerPk != newOwnerPk);
        vm.assume(wrongSignerPk != initialOwnerPk);

        address newOwner = vm.addr(newOwnerPk);

        vm.prank(initialOwner);
        account.addOwnerAddress(newOwner);

        (PackedUserOperation memory userOp, bytes32 userOpHash) = preparePackedUserOp.generateSignedUserOperation(
            CALLDATA, newOwner, wrongSignerPk, networkConfig.entryPointAddress, false
        );

        JustanAccount.SignatureWrapper memory sigWrapper =
            JustanAccount.SignatureWrapper({ ownerIndex: 1, signatureData: userOp.signature });

        userOp.signature = abi.encode(sigWrapper);

        vm.prank(networkConfig.entryPointAddress);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, SIG_VALIDATION_FAILED);
    }

}
