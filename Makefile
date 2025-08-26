-include .env

.PHONY: all test clean deploy fund help install snapshot format anvil zktest

DEFAULT_ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

all: clean remove install update build

# Clean the repo
clean  :; forge clean

# Remove modules
remove :; rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules && git add . && git commit -m "modules"

install :; forge install eth-infinitism/account-abstraction@v0.8.0 && forge install vectorized/solady && forge install OpenZeppelin/openzeppelin-contracts

# Update Dependencies
update:; forge update

build:; forge build

test :; forge test

snapshot :; forge snapshot

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

deploy:
	@forge script script/DeployJustanAccount.s.sol:DeployJustanAccount $(NETWORK_ARGS)

NETWORK_ARGS := --rpc-url http://localhost:8545 --account $(LOCAL_ACCOUNT) --broadcast

ifeq ($(findstring --network mainnet,$(ARGS)),--network mainnet)
	NETWORK_ARGS := --rpc-url $(MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 1 --delay 30 --retries 3 -vvvv
endif

ifeq ($(findstring --network sepolia,$(ARGS)),--network sepolia)
	NETWORK_ARGS := --rpc-url $(SEPOLIA_RPC_URL) --account $(SEPOLIA_ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 11155111 --delay 30 --retries 3 -vvvv
endif

ifeq ($(findstring --network arb-mainnet,$(ARGS)),--network arb-mainnet)
	NETWORK_ARGS := --rpc-url $(ARB_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 42161 -vvvv
endif

ifeq ($(findstring --network arb-sepolia,$(ARGS)),--network arb-sepolia)
	NETWORK_ARGS := --rpc-url $(ARB_SEPOLIA_RPC_URL) --account $(SEPOLIA_ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 421614 -vvvv
endif

ifeq ($(findstring --network base-mainnet,$(ARGS)),--network base-mainnet)
	NETWORK_ARGS := --rpc-url $(BASE_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 8453 -vvvv
endif

ifeq ($(findstring --network base-sepolia,$(ARGS)),--network base-sepolia)
	NETWORK_ARGS := --rpc-url $(BASE_SEPOLIA_RPC_URL) --account $(SEPOLIA_ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 84532 -vvvv
endif

ifeq ($(findstring --network op-mainnet,$(ARGS)),--network op-mainnet)
	NETWORK_ARGS := --rpc-url $(OP_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 10 -vvvv
endif

ifeq ($(findstring --network op-sepolia,$(ARGS)),--network op-sepolia)
	NETWORK_ARGS := --rpc-url $(OP_SEPOLIA_RPC_URL) --account $(SEPOLIA_ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 11155420 -vvvv
endif

deploy-mainnet:
	@forge script script/DeployJustanAccount.s.sol:DeployJustanAccount $(NETWORK_ARGS)

deploy-sepolia:
	@forge script script/DeployJustanAccount.s.sol:DeployJustanAccount $(NETWORK_ARGS)

deploy-base-mainnet:
	@forge script script/DeployJustanAccount.s.sol:DeployJustanAccount $(NETWORK_ARGS)

deploy-base-sepolia:
	@forge script script/DeployJustanAccount.s.sol:DeployJustanAccount $(NETWORK_ARGS)

deploy-op-mainnet:
	@forge script script/DeployJustanAccount.s.sol:DeployJustanAccount $(NETWORK_ARGS)	

deploy-op-sepolia:
	@forge script script/DeployJustanAccount.s.sol:DeployJustanAccount $(NETWORK_ARGS)

deploy-arb-mainnet:
	@forge script script/DeployJustanAccount.s.sol:DeployJustanAccount $(NETWORK_ARGS)	

deploy-arb-sepolia:
	@forge script script/DeployJustanAccount.s.sol:DeployJustanAccount $(NETWORK_ARGS)
