# RISC Lido Accounting Oracle

Implements a second-opinion accounting oracle for Lido compatible with [LIP-23](https://github.com/lidofinance/lido-improvement-proposals/blob/develop/LIPS/lip-23.md) using RISC Zero

This oracle performs provable computation over historical beacon state to determine at a given slot:

- *clBalanceGwei* - The total balance held by Lido validators
- *totalDepositedValidators* - The number of Lido validators ever to deposit
- *totalExitedValidators* - The number of Lido validators that have exited
- *withdrawalVaultBalance* - The balance of the WithdrawalVault contract on the execution layer

## Design

The proof makes use of the [Steel](https://docs.boundless.network/developers/steel/what-is-steel) to read historical execution layer state in a way that is later verified on-chain with a single commitment. Steel is used to read the withdrawal vault balance and also to obtain a trusted beacon block root at the desired slot via [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).

Given this trusted beacon root a number of SSZ merkle multiproofs are used to verifiably read the required beacon state data to compute the rest of the report. This includes the withdrawal credentials, exit status, and balance for every validator. This is reduced into the `totalDepositedValidators`, `totalExitedValidators`, and `clBalanceGwei` values for the oracle report.

## Development

### Prerequisites

First, [install Rust][install-rust] and [Foundry][install-foundry], and then restart your terminal.

```sh
# Install Rust
curl https://sh.rustup.rs -sSf | sh
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
```

Next, you will use `rzup` to install `cargo-risczero`.

To install `rzup`, run the following command and follow the instructions:

```sh
curl -L https://risczero.com/install | bash
```

Next we can install the RISC Zero toolchain by running `rzup`:

```sh
rzup install
```

You can verify the installation was successful by running:

```sh
cargo risczero --version
```

This repo uses [just](https://github.com/casey/just) as a command runner. Installation instructions [here](https://github.com/casey/just?tab=readme-ov-file#installation)

## Running tests

Use

```shell
just test
```

Attempting to run tests with `cargo test` will fail unless you can generate proofs locally, and even then it will take a long time.

## Usage

### Configuration

Building proofs requires access to a beacon chain RPC (that supports the `debug_` methods), an execution layer RPC, and a proving service (e.g. Bonsai or Boundless). 

> [!IMPORTANT]
> Many beacon chain RPC provides do not support the required debug methods for retrieving beacon state to build a proof. Quiknode is known to provide this but there may also be others.

These are configured via environment variables. Copy the [.env.example] to a .env file in the repo root and configure for your remote services.

### Contract Deployment

Simple deployment with

```shell
just deploy
```

This will read the .env file for RPC and other params.

See the [deployment guide](./docs/deployment-guide.md) for instructions on deploying to different chains

> [!IMPORTANT]
> Don't forget to obtain the deployed contract address and paste it in the .env file if you want to submit via the CLI

### Simple Usage via CLI

Using the justfile scripts provides a simple way to get started and examples of using the CLI. These will write intermediate proof files into the current directory.
These are mostly included for example usage of the CLI. For a production deployment use the CLI directly as required.

#### Create proof

To create a proof run

```shell
just prove <slot>
```

#### Submit on-chain


Submit on-chain with:

```shell
just submit <slot>
```

#### More advanced usage

Using the CLI directly provides more flexibility. See the help and subcommands help

```
CLI for generating and submitting Lido oracle proofs

Usage: cli --slot <SLOT> --eth-rpc-url <ETH_RPC_URL> <COMMAND>

Commands:
  gen-input  Generate the input needed to generate a proof This is to support proof generation using Boundless or Bonsai or other remote proving services
  prove      Generate a proof from a given input
  submit     Submit an aggregation proof to the oracle contract
  help       Print this message or the help of the given subcommand(s)

Options:
      --slot <SLOT>                slot at which to base the proofs
      --eth-rpc-url <ETH_RPC_URL>  Ethereum Node endpoint [env: ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/9SerMqClEQaLWRtdE2mclueU6PuaOy4-/]
  -h, --help                       Print help
  -V, --version                    Print version
```

## Security Disclaimer

Code is unaudited and not yet ready for production use
