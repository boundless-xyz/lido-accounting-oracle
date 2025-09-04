// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod beacon_client;

use alloy::{
    dyn_abi::SolType, network::EthereumWallet, primitives::Address, providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result};
use beacon_client::BeaconClient;
use clap::Parser;
use ethereum_consensus::{
    phase0::mainnet::{HistoricalBatch, SLOTS_PER_HISTORICAL_ROOT},
    ssz::prelude::Serialize,
};
use lido_oracle_core::{
    input::Input,
    mainnet::{WITHDRAWAL_CREDENTIALS, WITHDRAWAL_VAULT_ADDRESS},
    ETH_SEPOLIA_CHAIN_SPEC,
};
use oracle_builder::{MAINNET_ELF, MAINNET_ID};
use risc0_ethereum_contracts::encode_seal;
use risc0_steel::{ethereum::EthEvmEnv, Account};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext};
use std::{
    fs::{read, write},
    path::PathBuf,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use url::Url;

alloy::sol!(
    struct Report {
        uint256 clBalanceGwei;
        uint256 withdrawalVaultBalanceWei;
        uint256 totalDepositedValidators;
        uint256 totalExitedValidators;
    }

    struct Commitment {
        uint256 id;
        bytes32 digest;
        bytes32 configID;
    }

    /// @title Receiver of oracle reports and proof data
    #[sol(rpc, all_derives)]
    interface IOracleProofReceiver {
        function update(uint256 refSlot, Report calldata r, bytes calldata seal, Commitment calldata commitment) external;
    }
);

alloy::sol!(
    #[sol(rpc, all_derives)]
    "../contracts/src/ITestVerifier.sol"
);

/// CLI for generating and submitting Lido oracle proofs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// slot at which to base the proofs
    #[clap(long)]
    slot: u64,

    /// Ethereum Node endpoint.
    #[clap(long, env)]
    eth_rpc_url: Url,

    #[clap(subcommand)]
    command: Command,
}

/// Subcommands of the publisher CLI.
#[derive(Parser, Debug)]
enum Command {
    /// Generate the input needed to generate a proof
    /// This is to support proof generation using Boundless or Bonsai or other remote proving services
    GenInput {
        /// Ethereum beacon node HTTP RPC endpoint.
        #[clap(long, env)]
        beacon_rpc_url: Url,

        #[clap(long = "out", short)]
        out_path: PathBuf,

        #[clap(subcommand)]
        command: ProveCommand,
    },
    /// Generate a proof from a given input
    Prove {
        /// Ethereum beacon node HTTP RPC endpoint.
        #[clap(long, env)]
        beacon_rpc_url: Url,

        #[clap(long = "out", short)]
        out_path: PathBuf,

        #[clap(subcommand)]
        command: ProveCommand,
    },
    /// Submit an aggregation proof to the oracle contract
    Submit {
        /// Eth key to sign with
        #[clap(long, env)]
        eth_wallet_private_key: PrivateKeySigner,

        /// SecondOpinionOracle contract address
        #[clap(long, env)]
        contract: Option<Address>,

        /// TestVerifier contract address
        #[clap(long, env)]
        test_contract: Option<Address>,

        #[clap(long = "proof", short)]
        proof_path: PathBuf,
    },
}

#[derive(Parser, Debug)]
enum ProveCommand {
    /// An initial membership proof
    Initial,
    /// An aggregation (oracle) proof that can be submitted on-chain
    ContinuationFrom {
        prior_proof_path: PathBuf,

        // Ethereum execution node HTTP RPC endpoint.
        #[clap(long, env)]
        eth_rpc_url: Url,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    match args.command {
        Command::GenInput {
            out_path,
            command,
            beacon_rpc_url,
        } => {
            let input = match command {
                ProveCommand::Initial => {
                    build_input(args.slot, beacon_rpc_url, args.eth_rpc_url).await?
                }
                ProveCommand::ContinuationFrom {
                    prior_proof_path,
                    eth_rpc_url,
                } => {
                    todo!();
                }
            };

            // write as a frame in the VM stdin format
            let payload = bincode::serialize(&input)?;
            let len = payload.len() as u32;
            let mut vm_stdin = Vec::<u8>::new();
            vm_stdin.extend_from_slice(&len.to_le_bytes());
            vm_stdin.extend_from_slice(&payload);

            write(out_path, &bincode::serialize(&vm_stdin)?)?;
        }
        Command::Prove {
            beacon_rpc_url,
            out_path,
            command,
        } => {
            let input = match command {
                ProveCommand::Initial => {
                    build_input(args.slot, beacon_rpc_url, args.eth_rpc_url).await?
                }
                ProveCommand::ContinuationFrom {
                    prior_proof_path,
                    eth_rpc_url,
                } => {
                    todo!();
                }
            };

            let proof = build_proof(input, args.slot).await?;
            write(out_path, bincode::serialize(&proof)?)?;
        }
        Command::Submit {
            eth_wallet_private_key,
            contract,
            test_contract,
            proof_path,
        } => {
            submit_proof(
                eth_wallet_private_key,
                args.eth_rpc_url,
                contract,
                test_contract,
                proof_path,
            )
            .await?
        }
    }

    Ok(())
}

/// Wire format for an oracle proof that includes the slot and a receipt.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Proof {
    slot: u64,
    receipt: Receipt,
}

#[tracing::instrument(skip(beacon_rpc_url, eth_rpc_url))]
async fn build_input<'a>(
    slot: u64,
    beacon_rpc_url: Url,
    eth_rpc_url: Url,
) -> Result<Input<'a, Receipt>> {
    let beacon_client = BeaconClient::new_with_cache(beacon_rpc_url, "./beacon-cache")?;
    let provider = ProviderBuilder::new().connect_http(eth_rpc_url);

    let beacon_block_header = beacon_client.get_block_header(slot).await?;
    let beacon_state = beacon_client.get_beacon_state(slot).await?;

    let input = Input::<Receipt>::build_initial(
        &ETH_SEPOLIA_CHAIN_SPEC,
        MAINNET_ID,
        &beacon_block_header.message,
        &beacon_state,
        &WITHDRAWAL_CREDENTIALS,
        WITHDRAWAL_VAULT_ADDRESS,
        provider,
    )
    .await?;

    Ok(input)
}

async fn build_proof<'a>(input: Input<'a, Receipt>, slot: u64) -> Result<Proof> {
    let env = ExecutorEnv::builder()
        .write_frame(&bincode::serialize(&input)?)
        .build()?;

    tracing::info!("Generating proof...");
    let session_info = default_prover().prove_with_ctx(
        env,
        &VerifierContext::default(),
        MAINNET_ELF,
        &ProverOpts::groth16(),
    )?;
    tracing::info!("total cycles: {}", session_info.stats.total_cycles);

    Ok(Proof {
        slot,
        receipt: session_info.receipt,
    })
}

async fn submit_proof(
    eth_wallet_private_key: PrivateKeySigner,
    eth_rpc_url: Url,
    contract: Option<Address>,
    test_contract: Option<Address>,
    in_path: PathBuf,
) -> Result<()> {
    let wallet = EthereumWallet::from(eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(eth_rpc_url);

    let proof: Proof = bincode::deserialize(&read(in_path)?)?;
    tracing::info!("verifying locally for sanity check");
    proof.receipt.verify(MAINNET_ID)?;
    tracing::info!("Local verification passed :)");

    let seal = encode_seal(&proof.receipt).context("encoding seal")?;

    if let Some(test_contract) = test_contract {
        let contract = ITestVerifier::new(test_contract, provider.clone());
        let block_root = proof.receipt.journal.bytes[..32].try_into()?;
        let report = TestReport::abi_decode(&proof.receipt.journal.bytes[32..])?;
        let call_builder = contract.verify(block_root, report, seal.clone().into());
        let pending_tx = call_builder.send().await?;
        tracing::info!(
            "test_verifier: Submitted proof with tx hash: {}",
            pending_tx.tx_hash()
        );
        let tx_receipt = pending_tx.get_receipt().await?;
        tracing::info!("Test_verifier: Tx included with receipt {:?}", tx_receipt);
    }

    if let Some(contract) = contract {
        let contract = IOracleProofReceiver::new(contract, provider.clone());
        // skip the first 32 bytes of the journal as that is the beacon block hash which is not part of the report
        let report = Report::abi_decode(&proof.receipt.journal.bytes[32..])?;
        let commitment = Commitment::abi_decode(&proof.receipt.journal.bytes[32 + 32..])?;
        let call_builder = contract.update(
            proof.slot.try_into()?,
            report,
            seal.clone().into(),
            commitment,
        );
        let pending_tx = call_builder.send().await?;
        tracing::info!("Submitted proof with tx hash: {}", pending_tx.tx_hash());
        let tx_receipt = pending_tx.get_receipt().await?;
        tracing::info!("Tx included with receipt {:?}", tx_receipt);
    }

    if let (None, None) = (contract, test_contract) {
        eprintln!("No contract address provided, skipping submission");
    }

    Ok(())
}
