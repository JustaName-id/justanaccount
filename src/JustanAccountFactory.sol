// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { LibClone } from "solady/utils/LibClone.sol";

import { JustanAccount } from "./JustanAccount.sol";

contract JustanAccountFactory {

    /**
     * @notice Address of the JustanAccount implementation used as implementation for new accounts.
     */
    address private immutable i_implementation;

    /**
     * @notice Thrown when trying to create a new account without any owner.
     */
    error OwnerRequired();

    /**
     * @notice Factory constructor used to initialize the implementation address to use for future
     *              JustanAccount deployments.
     * @param implementation The address of the JustanAccount implementation.
     */
    constructor(address implementation) {
        i_implementation = implementation;
    }

    /**
     * @notice Returns the deterministic address for a JustanAccount created with `owners` and `nonce`
     *              deploys and initializes contract if it has not yet been created.
     * @dev Deployed as a ERC-1967 proxy that's implementation is `this.implementation`.
     * @param owners Array of initial owners. Each item should be an ABI encoded address or 64 byte public key.
     * @param nonce  The nonce of the account, a caller defined value which allows multiple accounts
     *              with the same `owners` to exist at different addresses.
     * @return account The address of the ERC-1967 proxy created with inputs `owners`, `nonce`, and
     *                 `this.implementation`.
     */
    function createAccount(
        bytes[] calldata owners,
        uint256 nonce
    )
        external
        payable
        virtual
        returns (JustanAccount account)
    {
        if (owners.length == 0) {
            revert OwnerRequired();
        }

        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(msg.value, i_implementation, _getSalt(owners, nonce));

        account = JustanAccount(payable(accountAddress));

        if (!alreadyDeployed) {
            account.initialize(owners);
        }
    }

    /**
     * @notice Returns the deterministic address of the account that would be created by `createAccount`.
     *
     * @param owners Array of initial owners. Each item should be an ABI encoded address or 64 byte public key.
     * @param nonce  The nonce provided to `createAccount()`.
     *
     * @return The predicted account deployment address.
     */
    function getAddress(bytes[] calldata owners, uint256 nonce) external view returns (address) {
        return LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(owners, nonce), address(this));
    }

    /**
     * @notice Returns the initialization code hash of the account:
     *         a ERC1967 proxy that's implementation is `this.implementation`.
     * @return The initialization code hash.
     */
    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(i_implementation);
    }

    /**
     * @notice Returns the implementation address used for new account deployments.
     * @return The address of the JustanAccount implementation contract.
     */
    function getImplementation() external view returns (address) {
        return i_implementation;
    }

    /**
     * @notice Returns the create2 salt for `LibClone.predictDeterministicAddress`
     *
     * @param owners Array of initial owners. Each item should be an ABI encoded address or 64 byte public key.
     * @param nonce  The nonce provided to `createAccount()`.
     *
     * @return The computed salt.
     */
    function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(owners, nonce));
    }

}
