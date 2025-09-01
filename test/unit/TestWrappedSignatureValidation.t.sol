// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@account-abstraction/core/Helpers.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { Test, Vm, console } from "forge-std/Test.sol";

import { DeployJustanAccount } from "../../script/DeployJustanAccount.s.sol";
import { HelperConfig } from "../../script/HelperConfig.s.sol";
import { CodeConstants } from "../../script/HelperConfig.s.sol";
import { PreparePackedUserOp } from "../../script/PreparePackedUserOp.s.sol";
import { JustanAccount } from "../../src/JustanAccount.sol";

/**
 * @title TestWrappedSignatureValidation
 * @notice Unit tests for SignatureWrapper validation (multi-owner ECDSA signatures)
 * @dev Tests the wrapped signature validation path in JustanAccount._validateSignature()
 *      for signatures longer than 65 bytes that use the SignatureWrapper struct
 */
contract TestWrappedSignatureValidation is Test, CodeConstants {

    JustanAccount public justanAccount;
    HelperConfig.NetworkConfig public networkConfig;
    PreparePackedUserOp public preparePackedUserOp;

    bytes CALLDATA = abi.encodeWithSignature("execute(address,uint256,bytes)", address(0), 0, "");

    function setUp() public {
        DeployJustanAccount deployer = new DeployJustanAccount();
        (justanAccount,, networkConfig) = deployer.run();

        preparePackedUserOp = new PreparePackedUserOp();

        // Delegate to the test account
        vm.signAndAttachDelegation(address(justanAccount), TEST_ACCOUNT_PRIVATE_KEY);
    }

    /*//////////////////////////////////////////////////////////////
                    WRAPPED SIGNATURE (SignatureWrapper) TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ShouldValidateWrappedSignature(uint256 newOwnerPk) public {
        vm.assume(newOwnerPk > 0 && newOwnerPk < SECP256K1_CURVE_ORDER);
        vm.assume(newOwnerPk != TEST_ACCOUNT_PRIVATE_KEY);
        
        address newOwner = vm.addr(newOwnerPk);

        vm.prank(TEST_ACCOUNT_ADDRESS);
        JustanAccount(TEST_ACCOUNT_ADDRESS).addOwnerAddress(newOwner);

        (PackedUserOperation memory userOp, bytes32 userOpHash) =
            preparePackedUserOp.generateSignedUserOperation(CALLDATA, networkConfig.entryPointAddress);

        // Create wrapped signature signed by the NEW OWNER's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwnerPk, userOpHash);
        bytes memory signatureData = abi.encodePacked(r, s, v);

        JustanAccount.SignatureWrapper memory sigWrapper = JustanAccount.SignatureWrapper({
            ownerIndex: 0, // Index of newOwner in owners array
            signatureData: signatureData
        });

        userOp.signature = abi.encode(sigWrapper);

        vm.prank(networkConfig.entryPointAddress);
        uint256 validationData = JustanAccount(TEST_ACCOUNT_ADDRESS).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, SIG_VALIDATION_SUCCESS);
    }

    function test_ShouldFailWrappedSignatureWithoutOwner(uint256 nonOwnerPk) public {
        vm.assume(nonOwnerPk > 0 && nonOwnerPk < SECP256K1_CURVE_ORDER);
        vm.assume(nonOwnerPk != TEST_ACCOUNT_PRIVATE_KEY);
        
        (PackedUserOperation memory userOp, bytes32 userOpHash) =
            preparePackedUserOp.generateSignedUserOperation(CALLDATA, networkConfig.entryPointAddress);

        // Create wrapped signature signed by the NON OWNER's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonOwnerPk, userOpHash);
        bytes memory signatureData = abi.encodePacked(r, s, v);

        JustanAccount.SignatureWrapper memory sigWrapper = JustanAccount.SignatureWrapper({
            ownerIndex: 0,
            signatureData: signatureData
        });

        userOp.signature = abi.encode(sigWrapper);

        vm.prank(networkConfig.entryPointAddress);
        uint256 validationData = JustanAccount(TEST_ACCOUNT_ADDRESS).validateUserOp(userOp, userOpHash, 0);

        // Should fail because NON OWNER is not an owner
        assertEq(validationData, SIG_VALIDATION_FAILED);
    }

    function test_ShouldFailWrappedSignatureWithWrongSigner(uint256 newOwnerPk, uint256 wrongSignerPk) public {
        vm.assume(newOwnerPk > 0 && newOwnerPk < SECP256K1_CURVE_ORDER);
        vm.assume(newOwnerPk != TEST_ACCOUNT_PRIVATE_KEY);

        vm.assume(wrongSignerPk > 0 && wrongSignerPk < SECP256K1_CURVE_ORDER);
        vm.assume(wrongSignerPk != newOwnerPk);
        vm.assume(wrongSignerPk != TEST_ACCOUNT_PRIVATE_KEY);
        
        address newOwner = vm.addr(newOwnerPk);

        // Add newOwner as owner at index 0
        vm.prank(TEST_ACCOUNT_ADDRESS);
        JustanAccount(TEST_ACCOUNT_ADDRESS).addOwnerAddress(newOwner);

        (PackedUserOperation memory userOp, bytes32 userOpHash) =
            preparePackedUserOp.generateSignedUserOperation(CALLDATA, networkConfig.entryPointAddress);

        // Create wrapped signature signed by wrongSigner (who is NOT an owner)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongSignerPk, userOpHash);
        bytes memory signatureData = abi.encodePacked(r, s, v);

        JustanAccount.SignatureWrapper memory sigWrapper = JustanAccount.SignatureWrapper({
            ownerIndex: 0,
            signatureData: signatureData
        });

        userOp.signature = abi.encode(sigWrapper);

        vm.prank(networkConfig.entryPointAddress);
        uint256 validationData = JustanAccount(TEST_ACCOUNT_ADDRESS).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, SIG_VALIDATION_FAILED);
    }

}