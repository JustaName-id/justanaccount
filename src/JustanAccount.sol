// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { Receiver } from "@solady/accounts/Receiver.sol";
import { ECDSA } from "@solady/utils/ECDSA.sol";
import { EIP712 } from "@solady/utils/EIP712.sol";
import { LibBit } from "@solady/utils/LibBit.sol";
import { WebAuthn } from "@solady/utils/WebAuthn.sol";

import { BaseAccount } from "@account-abstraction/core/BaseAccount.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "@account-abstraction/core/Helpers.sol";
import { IAccount } from "@account-abstraction/interfaces/IAccount.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IERC1155Receiver } from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import { MultiOwnable } from "./MultiOwnable.sol";

/**
 * @title JustanAccount
 * @notice This contract is to be used via EIP-7702 delegation and supports ERC-4337
 */
contract JustanAccount is BaseAccount, MultiOwnable, IERC165, IERC1271, Receiver, EIP712 {

    error JustanAccount_AlreadyInitialized();

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
     * @notice Returns entrypoint used by this account
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return i_entryPoint;
    }

    /**
     * @notice Validates the signature of the account.
     * @param hash The hash of the signed message.
     * @param signature The signature of the message.
     * @return result The result of the signature validation.
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 result) {
        bool success = _checkSignature({ hash: replaySafeHash(hash), signature: signature });
        assembly {
            // `success ? bytes4(keccak256("isValidSignature(bytes32,bytes)")) : 0xffffffff`.
            // We use `0xffffffff` for invalid, in convention with the reference implementation.
            result := shl(224, or(0x1626ba7e, sub(0, iszero(success))))
        }
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
     * @notice Produces a replay-safe hash from the given `hash`.
     * @dev The returned EIP-712 compliant replay-safe hash is the result of:
     *      keccak256(
     *         \x19\x01 ||
     *         this.domainSeparator ||
     *         hashStruct(JustanAccount({ hash: `hash`}))
     *      )
     * @param hash The original hash.
     * @return The corresponding replay-safe hash.
     */
    function replaySafeHash(bytes32 hash) public view virtual returns (bytes32) {
        return _hashTypedData(hash);
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
        return _checkSignature(userOpHash, userOp.signature) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    /**
     * @notice Validates signature.
     * @dev Checks whether the recovered address is equal to the account address or is an owner of this account.
     */
    function _checkSignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));

        if (LibBit.or(sigWrapper.signatureData.length == 64, sigWrapper.signatureData.length == 65)) {
            address recovered = ECDSA.tryRecover(hash, sigWrapper.signatureData);
            return (recovered != address(0) && (recovered == address(this) || isOwnerAddress(recovered)));
        }

        return _checkWebAuthnSignature(hash, signature);
    }

    /**
     * @notice Validates WebAuthn signature against all registered WebAuthn public keys.
     * @param hash The hash to verify.
     * @param signature The WebAuthn signature data.
     * @return True if signature is valid for any registered WebAuthn key.
     */
    function _checkWebAuthnSignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));

        // Check if owner index is valid
        if (sigWrapper.ownerIndex >= nextOwnerIndex()) {
            return false;
        }

        bytes memory ownerBytes = ownerAtIndex(sigWrapper.ownerIndex);

        // Check if it's a valid WebAuthn key (64 bytes) and is still an owner
        if (ownerBytes.length != 64 || !isOwnerBytes(ownerBytes)) {
            return false;
        }

        // Decode public key coordinates
        (bytes32 x, bytes32 y) = abi.decode(ownerBytes, (bytes32, bytes32));

        return _verifyWebAuthnSignature(hash, sigWrapper.signatureData, x, y);
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
