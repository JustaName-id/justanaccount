# JustanAccount

## Overview

The `JustanAccount` is a Solidity smart contract designed to enhance Ethereum account functionalities by integrating support for EIP-7702 and EIP-4337. These integrations enable features such as transaction batching, gas fee sponsorship, and advanced signature validation...

## Features

- **Multi-Owner Support**: Allows multiple owners to control the account, with flexible owner management including addition and removal of owners. This essentially allows the account to be used with advanced functionalities such as Coinbase's [SpendPermissionManager.sol](https://github.com/coinbase/spend-permissions).
- **Flexible Owner Types**: Supports both Ethereum addresses (20 bytes) and WebAuthn public keys (64 bytes), with architecture designed for future owner type expansion.
- **WebAuthn Signature Support**: Full support for WebAuthn authentication. Owners can be registered as 64-byte public key coordinates (x, y) and authenticate using modern web authentication standards.
- **ECDSA Signature Validation**: Traditional Ethereum signature support for both 64-byte and 65-byte ECDSA signatures.
- **Transaction Batching**: Allows the execution of multiple transactions in a single call, reducing overhead and improving efficiency.
- **Gas Sponsorship**: Supports mechanisms for third parties to sponsor gas fees, enabling users to interact with the Ethereum network without holding ETH.​
- **EIP-7702 Delegation**: Can be used as a delegated implementation for existing EOA wallets, enhancing them with smart contract capabilities.
- **EIP-4337 Account Abstraction**: Full compliance with account abstraction standards including UserOperation validation and EntryPoint integration.
- **ERC-7739 Compliant Signature Validation**: Implements advanced signature validation with ERC-7739 nested EIP-712 support, preventing signature replay attacks across accounts while maintaining readable typed data for wallet UIs.
- **Signature Validation**: Implements the `isValidSignature` function in compliance with EIP-1271 and ERC-7739, facilitating contract-based signature verification with replay protection.
- **Token Support**: Built-in support for receiving ERC-721 and ERC-1155 tokens.
- **Namespaced Storage**: Uses ERC-7201 standard for collision-resistant storage layout, ensuring safe delegation usage.

## Architecture

The contract consists of two main components:

### JustanAccount (Main Contract)

The primary account contract that inherits from:

- BaseAccount (ERC-4337 compliance)
- Receiver (Solady's receive functionality)
- MultiOwnable (Multi-owner management)
- ERC1271 (Solady's ERC-1271 with ERC-7739 support)
- IERC165 (Interface support)

#### Key Components

- `execute` Function: Executes a single transaction to a target address with specified value and data. Ensures that the caller is authorized (either the eoa through 7702, an account owner or the designated entry point).
- `executeBatch` Function: Executes multiple transactions in a single call. If any transaction fails, the function reverts, indicating the index of the failed transaction.
- `entryPoint` Function: Returns the entry point contract associated with this account, as required by EIP-4337.
- `isValidSignature` Function: Validates signatures according to EIP-1271 and ERC-7739, supporting both ECDSA and WebAuthn signature schemes with nested EIP-712 replay protection.
- `supportsInterface` Function: Indicates support for various interfaces, including ERC165, IAccount, IERC1271, IERC1155Receiver, and IERC721Receiver.
- `_validateSignature` Function: Internal EIP-4337 signature validation for UserOperations.
- `_checkSignature` Function: Core signature validation logic supporting multiple signature types.
- `_checkWebAuthnSignature` Function: Validates WebAuthn signatures against all registered WebAuthn public keys.
- `_verifyWebAuthnSignature` Function: Verifies individual WebAuthn signatures using Solady's WebAuthn library.

#### Signature Support

The contract supports multiple signature schemes:

1. **ECDSA Signatures** (64 or 65 bytes):

   - Standard Ethereum signatures
   - Validates against registered address owners
   - Validates against the account address itself (for EIP-7702 delegation)

2. **WebAuthn Signatures**:
   - Modern web authentication standard
   - Supports Touch ID, Face ID, and hardware security keys
   - Uses P-256 elliptic curve cryptography
   - Validates against registered 64-byte public key coordinates

#### ERC-7739 Implementation

The contract implements ERC-7739 (Readable Typed Signatures for Smart Accounts) through Solady's ERC1271 base contract, providing:

1. **Nested EIP-712 Support**:

   - Prevents signature replay attacks across different smart accounts
   - Maintains readable typed data for wallet UIs
   - Supports both TypedDataSign and PersonalSign workflows

2. **Automatic Detection**:

   - Returns magic value `0x77390001` when called with hash `0x7739...7739`
   - Enables wallets to detect ERC-7739 support automatically

3. **Security Features**:

   - Domain separator includes contract address and chain ID
   - Defensive rehashing prevents cross-account signature reuse
   - Compatible with existing EIP-712 wallet infrastructure

4. **Workflow Support**:
   - **TypedDataSign**: For typed structured data with full EIP-712 compatibility
   - **PersonalSign**: For personal messages with Ethereum signed message prefix
   - **RPC Validation**: Special handling for off-chain signature validation

### MultiOwnable (Owner Management)

A separate contract that provides multi-owner functionality with:

- ERC-7201 Namespaced Storage: Prevents storage collisions using the storage slot 0x548403af3b7bfc881040446090ff025838396ebf051dc219a19859cf4ef8e800
- Flexible Owner Types: Stores owners as bytes to support both Ethereum addresses and WebAuthn public keys
- Index-based Management: Efficient owner tracking and removal using indices

#### Key Components

- `addOwnerAddress(address owner)`: Adds a new Ethereum address as an owner
- `addOwnerPublicKey(bytes32 x, bytes32 y)`: Adds a new WebAuthn public key as an owner
- `removeOwnerAtIndex(uint256 index, bytes calldata owner)`: Removes an owner at a specific index (requires multiple owners)
- `removeLastOwner(uint256 index, bytes calldata owner)`: Removes the final owner (special case)
- `isOwnerAddress(address account)`: Checks if an address is a registered owner
- `isOwnerPublicKey(bytes32 x, bytes32 y)`: Checks if a WebAuthn public key is a registered owner
- `isOwnerBytes(bytes memory account)`: Checks if bytes data represents a registered owner
- `ownerAtIndex(uint256 index)`: Returns the owner data at a specific index
- `ownerCount()`: Returns the current number of active owners
- `nextOwnerIndex()`: Returns the next index to be used for owner addition
- `removedOwnersCount()`: Returns the number of owners that have been removed

## Authorization Model

The contract implements a hierarchical authorization system:

1. **Primary Authorization**:

   - EOA owner through EIP-7702 delegation (`msg.sender == address(this)`)
   - EIP-4337 EntryPoint for UserOperations

2. **Secondary Authorization**:

   - Registered Ethereum address owners
   - Registered WebAuthn public key owners

3. **Signature Validation Priority**:
   - First attempts ECDSA signature validation (64/65 byte signatures)
   - Falls back to WebAuthn signature validation for other signature formats
   - Validates against all registered owners of the appropriate type

## Storage Layout

The contract uses ERC-7201 namespaced storage to prevent collisions:

```solidity
// Storage slot: keccak256(abi.encode(uint256(keccak256("justanaccount.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
bytes32 private constant MULTI_OWNABLE_STORAGE_LOCATION = 0x548403af3b7bfc881040446090ff025838396ebf051dc219a19859cf4ef8e800;
```

### Storage Structure

```solidity
struct MultiOwnableStorage {
    uint256 s_nextOwnerIndex;           // Index for next owner addition
    uint256 s_removedOwnersCount;       // Track removed owners count
    mapping(uint256 => bytes) s_ownerAtIndex;    // Index to owner bytes mapping
    mapping(bytes => bool) s_isOwner;            // Owner existence mapping
}
```
