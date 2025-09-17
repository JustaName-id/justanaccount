// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { ERC1271 } from "@solady/accounts/ERC1271.sol";
import { Receiver } from "@solady/accounts/Receiver.sol";
import { ECDSA } from "@solady/utils/ECDSA.sol";
import { LibBit } from "@solady/utils/LibBit.sol";
import { SignatureCheckerLib } from "@solady/utils/SignatureCheckerLib.sol";
import { WebAuthn } from "@solady/utils/WebAuthn.sol";

import { BaseAccount } from "@account-abstraction/core/BaseAccount.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "@account-abstraction/core/Helpers.sol";
import { UserOperationLib } from "@account-abstraction/core/UserOperationLib.sol";
import { Exec } from "@account-abstraction/utils/Exec.sol";
import { Eip7702Support } from "@account-abstraction/core/Eip7702Support.sol";
import { IAccount } from "@account-abstraction/interfaces/IAccount.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IERC1155Receiver } from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import { MultiOwnable } from "./MultiOwnable.sol";

/**
 * @title JustanAccount
 * @notice This contract is to be used via EIP-7702 delegation and supports ERC-4337
 */
contract JustanAccount is BaseAccount, MultiOwnable, IERC165, Receiver, ERC1271 {

    using UserOperationLib for PackedUserOperation;

    /**
     * @notice Thrown when attempting to initialize an already initialized account.
     */
    error JustanAccount_AlreadyInitialized();

    /**
     * @notice Thrown when a call is passed to `executeWithoutChainIdValidation` that is not allowed by
     *         `canSkipChainIdValidation`
     *
     * @param selector The selector of the call.
     */
    error JustanAccount_SelectorNotAllowed(bytes4 selector);

    /**
     * @notice Thrown in validateUserOp if the key of `UserOperation.nonce` does not match the calldata.
     *
     * @dev Calls to `this.executeWithoutChainIdValidation` MUST use `REPLAYABLE_NONCE_KEY` and
     *      calls NOT to `this.executeWithoutChainIdValidation` MUST NOT use `REPLAYABLE_NONCE_KEY`.
     *
     * @param key The invalid `UserOperation.nonce` key.
     */
    error JustanAccount_InvalidNonceKey(uint256 key);

    struct SignatureWrapper {
        /// @dev The index of the owner that signed, see `MultiOwnable.ownerAtIndex`
        uint256 ownerIndex;
        /// @dev If `MultiOwnable.ownerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
        ///      If `MultiOwnable.ownerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
        bytes signatureData;
    }

    /**
     * @notice The entrypoint used by this account.
     * @dev This is set during the contract deployment and cannot be changed later.
     */
    IEntryPoint private immutable i_entryPoint;

    /**
     * @notice Reserved nonce key (upper 192 bits of `UserOperation.nonce`) for cross-chain replayable
     *         transactions.
     *
     * @dev MUST BE the `UserOperation.nonce` key when `UserOperation.calldata` is calling
     *      `executeWithoutChainIdValidation`and MUST NOT BE `UserOperation.nonce` key when `UserOperation.calldata` is
     *      NOT calling `executeWithoutChainIdValidation`.
     *
     * @dev Helps enforce sequential sequencing of replayable transactions.
     */
    uint256 public constant REPLAYABLE_NONCE_KEY = 9999;

    bytes32 private constant TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /**
     * @notice Initializes the JustanAccount contract with the entry point address.
     * @param entryPointAddress The address of the entry point contract.
     */
    constructor(address entryPointAddress) {
        i_entryPoint = IEntryPoint(entryPointAddress);

        // Implementation should not be initializable (does not affect proxies which use their own storage).
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(address(0));
        _initializeOwners(owners);
    }

    /**
     * @notice Executes `calls` on this account (i.e. self call).
     *
     * @dev Reverts if the given call is not authorized to skip the chain ID validation.
     * @dev `validateUserOp()` will recompute the `userOpHash` without the chain ID before validating
     *      it if the `UserOperation.calldata` is calling this function. This allows certain UserOperations
     *      to be replayed for all accounts sharing the same address across chains. E.g. This may be
     *      useful for syncing owner changes.
     *
     * @param calls An array of calldata to use for separate self calls.
     */
    function executeWithoutChainIdValidation(bytes[] calldata calls) external payable virtual {
        _requireForExecute();
        uint256 callsLength = calls.length;
        for (uint256 i; i < callsLength; i++) {
            bytes calldata call = calls[i];
            bytes4 selector = bytes4(call);
            if (!canSkipChainIdValidation(selector)) {
                revert JustanAccount_SelectorNotAllowed(selector);
            }

            bool ok = Exec.call(address(this), 0, call, gasleft());
            if (!ok) {
                Exec.revertWithReturnData();
            }
        }
    }

     /**
     * @notice Validates UserOperation with cross-chain support.
     * @dev Overrides BaseAccount to handle cross-chain replayable operations.
     * @param userOp The user operation to validate.
     * @param userOpHash The hash of the user operation from EntryPoint.
     * @param missingAccountFunds The missing account funds.
     * @return validationData The validation result.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        virtual
        override
        returns (uint256 validationData)
    {
        _requireFromEntryPoint();

        uint256 key = userOp.nonce >> 64;

        // Check if this is a cross-chain replayable operation
        if (bytes4(userOp.callData) == this.executeWithoutChainIdValidation.selector) {
            

            userOpHash = getUserOpHashWithoutChainId(userOp);

            if (key != REPLAYABLE_NONCE_KEY) {
                revert JustanAccount_InvalidNonceKey(key);
            }
        } else {
            if (key == REPLAYABLE_NONCE_KEY) {
                revert JustanAccount_InvalidNonceKey(key);
            }
        }

        validationData = _validateSignature(userOp, userOpHash);
        _validateNonce(userOp.nonce);
        _payPrefund(missingAccountFunds);
    }


    /**
     * @notice Returns entrypoint used by this account
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return i_entryPoint;
    }

    /**
     * @notice Computes the hash of a UserOperation in the same way as EntryPoint v0.8, but excludes the chain ID.
     * @dev This enables cross-chain replay of UserOperations with the same signature for certain operations.
     * @param userOp The user operation to hash.
     * @return The hash of the UserOperation without chain ID.
     */
    function getUserOpHashWithoutChainId(PackedUserOperation calldata userOp)
        public
        view
        virtual
        returns (bytes32)
    {
        bytes32 overrideInitCodeHash = Eip7702Support._getEip7702InitCodeHashOverride(userOp);
        return
            MessageHashUtils.toTypedDataHash(keccak256(abi.encode(TYPE_HASH, "ERC4337", "1", 0, address(entryPoint()))), userOp.hash(overrideInitCodeHash));
    }

    /**
     * @notice Validates the signature of the account using ERC-7739 compliant nested EIP-712.
     * @param hash The hash of the signed message.
     * @param signature The signature of the message.
     * @return result The result of the signature validation.
     */
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    )
        public
        view
        override (ERC1271)
        returns (bytes4 result)
    {
        return super.isValidSignature(hash, signature);
    }

    /**
     * @notice Checks if the contract supports an interface.
     * @param id The interface ID.
     * @return Whether the contract supports the interface.
     */
    function supportsInterface(bytes4 id) public pure override (IERC165) returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IAccount).interfaceId || id == type(IERC1271).interfaceId
            || id == type(IERC1155Receiver).interfaceId || id == type(IERC721Receiver).interfaceId;
    }

    /**
     * @notice Returns whether `functionSelector` can be called in `executeWithoutChainIdValidation`.
     *
     * @param functionSelector The function selector to check.
     * @return `true` is the function selector is allowed to skip the chain ID validation, else `false`.
     */
    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        if (
            functionSelector == MultiOwnable.addOwnerPublicKey.selector
                || functionSelector == MultiOwnable.addOwnerAddress.selector
                || functionSelector == MultiOwnable.removeOwnerAtIndex.selector
                || functionSelector == MultiOwnable.removeLastOwner.selector
        ) {
            return true;
        }
        return false;
    }

    /**
     * @notice Initializes the JustanAccount with the provided owners.
     * @dev Reverts if the account has had at least one owner, i.e. has been initialized.
     * @param owners Array of initial owners for this account. Each item should be
     *               an ABI encoded Ethereum address, i.e. 32 bytes with 12 leading 0 bytes,
     *               or a 64 byte public key.
     */
    function initialize(bytes[] calldata owners) external payable virtual {
        if (nextOwnerIndex() != 0) {
            revert JustanAccount_AlreadyInitialized();
        }

        _initializeOwners(owners);
    }

    /**
     * @notice Validates the signature of the account.
     * @dev Called by the entry point.
     * @param userOp The user operation.
     * @param userOpHash The hash of the user operation.
     * @return validationData The result of the signature validation.
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        return _erc1271IsValidSignatureNowCalldata(userOpHash, userOp.signature)
            ? SIG_VALIDATION_SUCCESS
            : SIG_VALIDATION_FAILED;
    }

    /**
     * @dev Validates the signature using custom logic for ECDSA and WebAuthn.
     * This overrides the default ECDSA-only validation to support multiple signature types.
     * Only handles wrapped signatures - unwrapped signatures use SignatureCheckerLib directly.
     */
    function _erc1271IsValidSignatureNowCalldata(
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
        virtual
        override
        returns (bool)
    {
        // Signature will not be wrapped if used via EIP-7702 delegation
        if (signature.length == 64 || signature.length == 65) {
            address recovered = ECDSA.tryRecover(hash, signature);
            return (recovered != address(0) && (recovered == _erc1271Signer()));
        }

        // Otherwise, treat as wrapped signature for owners logic
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        if (LibBit.or(sigWrapper.signatureData.length == 64, sigWrapper.signatureData.length == 65)) {
            address recovered = ECDSA.tryRecover(hash, sigWrapper.signatureData);
            return (recovered != address(0) && isOwnerAddress(recovered));
        }

        return _checkWebAuthnSignature(hash, sigWrapper.signatureData, sigWrapper.ownerIndex);
    }

    /**
     * @notice Checks if a WebAuthn signature is valid for a given owner index.
     * @param hash The hash to verify.
     * @param signatureData The WebAuthn signature data.
     * @param ownerIndex The index of the owner to verify against.
     * @return True if the signature is valid for the given owner index.
     */
    function _checkWebAuthnSignature(
        bytes32 hash,
        bytes memory signatureData,
        uint256 ownerIndex
    )
        internal
        view
        returns (bool)
    {
        // Check if owner index is valid
        if (ownerIndex >= nextOwnerIndex()) {
            return false;
        }

        bytes memory ownerBytes = ownerAtIndex(ownerIndex);

        // Check if it's a valid WebAuthn key (64 bytes) and is still an owner
        if (ownerBytes.length != 64 || !isOwnerBytes(ownerBytes)) {
            return false;
        }

        // Decode public key coordinates
        (bytes32 x, bytes32 y) = abi.decode(ownerBytes, (bytes32, bytes32));

        return _verifyWebAuthnSignature(hash, signatureData, x, y);
    }

    /**
     * @notice Verifies a single WebAuthn signature.
     * @param hash The hash to verify.
     * @param signature The WebAuthn signature data.
     * @param x The public key x coordinate.
     * @param y The public key y coordinate.
     * @return True if signature is valid.
     */
    function _verifyWebAuthnSignature(
        bytes32 hash,
        bytes memory signature,
        bytes32 x,
        bytes32 y
    )
        internal
        view
        returns (bool)
    {
        return WebAuthn.verify({
            challenge: abi.encode(hash),
            requireUserVerification: false,
            auth: WebAuthn.tryDecodeAuth(signature),
            x: x,
            y: y
        });
    }

    /**
     * @notice Checks if execution is allowed.
     */
    function _requireForExecute() internal view override {
        _checkOwnerOrEntryPoint();
    }

    /**
     * @notice Checks if the sender is an owner of this contract or the entrypoint.
     * @dev Reverts if the sender is not an owner of the contract or the entrypoint.
     */
    function _checkOwnerOrEntryPoint() internal view virtual override {
        if (msg.sender != address(entryPoint())) {
            _checkOwner();
        }
    }

    /**
     * @dev Required override from ERC1271 base contract.
     * For EIP-7702 delegation, the signer is this contract address.
     */
    function _erc1271Signer() internal view virtual override returns (address) {
        return address(this);
    }

    /**
     * @dev for EIP712
     */
    function _domainNameAndVersion()
        internal
        view
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "JustanAccount";
        version = "1";
    }

}
