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
    network::EthereumWallet, primitives::Address, providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use alloy_primitives::{utils::parse_ether, Bytes, B256, U256};
use anyhow::{bail, Result};
use beacon_client::BeaconClient;
use boundless_market::{
    request_builder::OfferParams, storage::storage_provider_from_env, Client, Deployment, GuestEnv,
    StorageProviderConfig,
};
use clap::Parser;
use lido_oracle_core::{
    generate_oracle_report, input::Input, mainnet, sepolia, soltypes::IBoundlessMarketCallback,
    ETH_MAINNET_CHAIN_SPEC, ETH_SEPOLIA_CHAIN_SPEC,
};
use oracle_builder::{MAINNET_ELF, MAINNET_ID, SEPOLIA_ELF, SEPOLIA_ID};
use risc0_steel::{config::ChainSpec, ethereum::EthEvmEnv, revm::primitives::hardfork::SpecId};
use risc0_zkvm::{
    default_prover, sha::Digestible, ExecutorEnv, InnerReceipt, ProverOpts, VerifierContext,
};
use std::{
    env,
    fs::{read, write},
    path::PathBuf,
    sync::LazyLock,
    time::Duration,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use url::Url;

/// CLI for generating and submitting Lido oracle proofs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
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
        /// slot at which to base the proofs
        #[clap(long)]
        slot: u64,

        /// Ethereum beacon node HTTP RPC endpoint.
        #[clap(long, env)]
        beacon_rpc_url: Url,

        #[clap(long = "out", short)]
        out_path: PathBuf,
    },
    /// Generate a proof from a given input
    Prove {
        /// slot at which to base the proofs
        #[clap(long)]
        slot: u64,

        /// Ethereum beacon node HTTP RPC endpoint.
        #[clap(long, env)]
        beacon_rpc_url: Url,

        #[clap(long = "out", short)]
        out_path: PathBuf,
    },
    /// Submit an aggregation proof to the oracle contract
    Submit {
        /// Eth key to sign with
        #[clap(long, env)]
        eth_wallet_private_key: PrivateKeySigner,

        /// SecondOpinionOracle contract address
        #[clap(long, env)]
        oracle_contract: Address,

        #[clap(long = "proof", short)]
        proof_path: PathBuf,
    },
    Daemon {
        /// Ethereum beacon node HTTP RPC endpoint.
        #[clap(long, env)]
        beacon_rpc_url: Url,

        #[clap(flatten, next_help_heading = "Boundless Config")]
        boundless_config: BoundlessConfig,

        /// Private key for Ethereum for submitting oracle reports
        #[clap(long, env)]
        eth_wallet_private_key: PrivateKeySigner,

        /// SecondOpinionOracle contract address
        #[clap(long, env)]
        oracle_contract: Address,
    },
}

/// Configuration for the requestor service.
#[derive(Parser, Debug)]
pub struct BoundlessConfig {
    #[clap(long, env)]
    pub boundless_rpc_url: Url,
    #[clap(long, env)]
    pub boundless_private_key: PrivateKeySigner,
    #[clap(flatten, next_help_heading = "Storage Provider")]
    pub storage_config: StorageProviderConfig,
    /// Deployment of the Boundless contracts and services to use.
    ///
    /// Will be automatically resolved from the connected chain ID if unspecified.
    #[clap(flatten, next_help_heading = "Boundless Market Deployment")]
    deployment: Option<Deployment>,
    /// URL that points to the oracle zkVM image
    #[clap(long, env)]
    pub image_url: Url,
    /// ETH threshold for submitting new requests.
    #[clap(long, value_parser = parse_ether, default_value = "0.01")]
    eth_threshold: U256,
    /// Maximum ETH price for requests.
    #[clap(long, value_parser = parse_ether, default_value = "0.1")]
    max_eth_price: U256,
    /// Lock collateral in raw value.
    ///
    /// Default value is 1 ZKC
    #[clap(long, default_value = "1000000000000000000")]
    lock_collateral: U256,
    /// Ramp up period in seconds.
    #[clap(long, default_value = "180")]
    ramp_up_period: u64,
    /// Lock timeout in seconds.
    #[clap(long, default_value = "300")]
    lock_timeout: u64,
    /// Request timeout in seconds.
    #[clap(long, default_value = "600")]
    timeout: u64,
    #[clap(long, default_value = "60")]
    ramp_up_start_delay: u64,
    /// Submission interval in seconds. How frequently checks how much ETH is available and sends requests.
    #[clap(long, default_value = "10")]
    submission_interval: u64,
    /// Status check interval in seconds. Checks the status of the previously submitted requests.
    #[clap(long, default_value = "20")]
    status_check_interval: u64,
    /// Maximum retry attempts for failed requests.
    #[clap(long, default_value = "3")]
    pub max_retries: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let (image_id, elf, spec, withdrawal_credentials, vault_address) = chain_values_from_env();

    match args.command {
        Command::GenInput {
            slot,
            out_path,
            beacon_rpc_url,
        } => {
            let input = build_input(slot, beacon_rpc_url, args.eth_rpc_url).await?;

            // sanity check
            let report = generate_oracle_report(
                input.clone(),
                spec,
                &withdrawal_credentials,
                vault_address,
            )?;
            tracing::info!("Input generates report: {:?}", report);

            // write as a frame in the VM stdin format
            let payload = bincode::serialize(&input)?;
            let len = payload.len() as u32;
            let mut vm_stdin = Vec::<u8>::new();
            vm_stdin.extend_from_slice(&len.to_le_bytes());
            vm_stdin.extend_from_slice(&payload);

            write(out_path, &vm_stdin)?;
        }
        Command::Prove {
            slot,
            beacon_rpc_url,
            out_path,
        } => {
            let input = build_input(slot, beacon_rpc_url, args.eth_rpc_url).await?;

            let proof = build_proof(image_id, elf, input, slot).await?;
            write(out_path, bincode::serialize(&proof)?)?;
        }
        Command::Submit {
            eth_wallet_private_key,
            proof_path,
            oracle_contract,
        } => {
            let proof: Proof = bincode::deserialize(&read(proof_path)?)?;
            submit_proof(
                image_id,
                eth_wallet_private_key,
                args.eth_rpc_url,
                oracle_contract,
                proof,
            )
            .await?
        }
        Command::Daemon {
            beacon_rpc_url,
            boundless_config,
            eth_wallet_private_key,
            oracle_contract,
        } => {
            tracing::info!("Starting daemon: polling beacon head every 12s");
            let beacon_client = BeaconClient::new(beacon_rpc_url.clone())?;

            let boundless_client = Client::builder()
                .with_deployment(boundless_config.deployment.clone())
                .with_rpc_url(boundless_config.boundless_rpc_url.clone())
                .with_private_key(boundless_config.boundless_private_key.clone())
                .with_storage_provider(Some(storage_provider_from_env()?))
                .build()
                .await?;

            loop {
                match beacon_client.get_block_header("finalized").await {
                    Ok(block) => {
                        let slot = block.message.slot;
                        tracing::info!("Current beacon finalized slot: {}", slot);
                        if is_frame_boundary(slot) {
                            tracing::info!("Generating report for slot: {}", slot);

                            let input =
                                build_input(slot, beacon_rpc_url.clone(), args.eth_rpc_url.clone())
                                    .await?;

                            let proof = build_proof_boundless(
                                &boundless_client,
                                &boundless_config,
                                input,
                                slot,
                            )
                            .await?;

                            submit_proof(
                                image_id,
                                eth_wallet_private_key.clone(),
                                args.eth_rpc_url.clone(),
                                oracle_contract,
                                proof,
                            )
                            .await?
                        }
                    }
                    Err(e) => tracing::warn!("Error requesting beacon head: {}", e),
                }

                tokio::time::sleep(std::time::Duration::from_secs(12)).await;
            }
        }
    }

    Ok(())
}

fn is_frame_boundary(slot: u64) -> bool {
    const SLOTS_PER_EPOCH: u64 = 32;
    const EPOCHS_PER_FRAME: u64 = 225;
    const SLOTS_PER_FRAME: u64 = SLOTS_PER_EPOCH * EPOCHS_PER_FRAME;
    slot % SLOTS_PER_FRAME == 0
}

/// Wire format for an oracle proof that includes the slot and a receipt.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Proof {
    slot: u64,
    journal: Bytes,
    seal: Bytes,
}

#[tracing::instrument(skip(beacon_rpc_url, eth_rpc_url))]
async fn build_input<'a>(slot: u64, beacon_rpc_url: Url, eth_rpc_url: Url) -> Result<Input<'a>> {
    let beacon_client = BeaconClient::new_with_cache(beacon_rpc_url.clone(), "./beacon-cache")?;
    let provider = ProviderBuilder::new().connect_http(eth_rpc_url);

    let beacon_block_header = beacon_client.get_block_header(slot).await?;
    let beacon_state = beacon_client.get_beacon_state(slot).await?;
    // It is important to get the beacon block at slot + 1 to ensure it can reference the desired beacon slot via EIP-4788
    let execution_block_hash = beacon_client.get_eth1_block_hash_at_slot(slot + 1).await?;

    let (_, _, spec, withdrawal_credentials, vault_address) = chain_values_from_env();

    // build the Steel input for reading the balance and block root
    let env = EthEvmEnv::builder()
        .provider(provider.clone())
        .beacon_api(beacon_rpc_url)
        .chain_spec(&spec)
        .block_hash(B256::from_slice(execution_block_hash.as_slice()))
        .build()
        .await
        .unwrap();

    let input = Input::build_beacon_commit(
        env,
        &beacon_block_header.message,
        &beacon_state,
        &withdrawal_credentials,
        vault_address,
    )
    .await?;

    Ok(input)
}

async fn build_proof<'a>(
    image_id: [u32; 8],
    elf: &[u8],
    input: Input<'a>,
    slot: u64,
) -> Result<Proof> {
    let env = ExecutorEnv::builder()
        .write_frame(&bincode::serialize(&input)?)
        .build()?;

    tracing::info!("Generating proof...");
    let session_info = default_prover().prove_with_ctx(
        env,
        &VerifierContext::default(),
        elf,
        &ProverOpts::groth16(),
    )?;
    tracing::info!("total cycles: {}", session_info.stats.total_cycles);

    tracing::info!("verifying locally for sanity check");
    session_info.receipt.verify(image_id)?;
    tracing::info!("Local verification passed :)");

    Ok(Proof {
        slot,
        seal: encode_seal(&session_info.receipt)?,
        journal: session_info.receipt.journal.bytes.into(),
    })
}

async fn build_proof_boundless<'a>(
    boundless_client: &Client,
    boundless_config: &BoundlessConfig,
    input: Input<'a>,
    slot: u64,
) -> Result<Proof> {
    let env = GuestEnv::builder()
        .write_frame(&bincode::serialize(&input)?)
        .build_env();

    let request = boundless_client
        .new_request()
        .with_env(env)
        .with_program_url(boundless_config.image_url.clone())?
        .with_groth16_proof()
        .with_offer(
            OfferParams::builder()
                .min_price(parse_ether("0.001")?)
                .max_price(parse_ether("0.002")?)
                .timeout(1000)
                .lock_timeout(500)
                .ramp_up_period(100),
        );

    let (request_id, expires_at) = boundless_client.submit_offchain(request).await?;

    let fulfillment = boundless_client
        .wait_for_request_fulfillment(
            request_id,
            Duration::from_secs(5), // check every 5 seconds
            expires_at,
        )
        .await?;
    tracing::info!("Request {:x} fulfilled", request_id);

    Ok(Proof {
        slot,
        journal: fulfillment
            .data()?
            .journal()
            .expect("missing journal")
            .clone(),
        seal: fulfillment.seal,
    })
}

async fn submit_proof(
    image_id: [u32; 8],
    eth_wallet_private_key: PrivateKeySigner,
    eth_rpc_url: Url,
    contract: Address,
    proof: Proof,
) -> Result<()> {
    let wallet = EthereumWallet::from(eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(eth_rpc_url);

    let contract = IBoundlessMarketCallback::new(contract, provider.clone());
    let call_builder = contract.handleProof(
        B256::from_slice(bytemuck::cast_slice(&image_id[..])),
        proof.journal,
        proof.seal,
    );
    let pending_tx = call_builder.send().await?;
    tracing::info!("Submitted proof with tx hash: {}", pending_tx.tx_hash());
    let tx_receipt = pending_tx.get_receipt().await?;
    tracing::info!("Tx included with receipt {:?}", tx_receipt);

    Ok(())
}

/// Encode the seal of the given receipt for use with EVM smart contract verifiers.
///
/// Appends the verifier selector, determined from the first 4 bytes of the verifier parameters
/// including the Groth16 verification key and the control IDs that commit to the RISC Zero
/// circuits.
///
/// copied here from risc0-ethereum-contracts crate as adding that crate creates a dependency hell with alloy
fn encode_seal(receipt: &risc0_zkvm::Receipt) -> Result<Bytes> {
    let seal = match receipt.inner.clone() {
        InnerReceipt::Fake(receipt) => {
            let seal = receipt.claim.digest().as_bytes().to_vec();
            let selector = &[0xFFu8; 4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(&seal);
            selector_seal
        }
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(receipt.seal.as_ref());
            selector_seal
        }
        _ => bail!("Unsupported receipt type"),
    };
    Ok(Bytes::from(seal))
}

/// Read the ETH_NETWORK env var and return the corresponding chain values
fn chain_values_from_env() -> (
    [u32; 8],
    &'static [u8],
    &'static LazyLock<ChainSpec<SpecId>>,
    alloy_primitives::FixedBytes<32>,
    alloy_primitives::Address,
) {
    match env::var("ETH_NETWORK").unwrap_or_else(|_| "mainnet".to_string()) {
        ref s if s == "mainnet" => (
            MAINNET_ID,
            MAINNET_ELF,
            &ETH_MAINNET_CHAIN_SPEC,
            mainnet::WITHDRAWAL_CREDENTIALS,
            mainnet::WITHDRAWAL_VAULT_ADDRESS,
        ),
        ref s if s == "sepolia" => (
            SEPOLIA_ID,
            SEPOLIA_ELF,
            &ETH_SEPOLIA_CHAIN_SPEC,
            sepolia::WITHDRAWAL_CREDENTIALS,
            sepolia::WITHDRAWAL_VAULT_ADDRESS,
        ),
        other => panic!("Unsupported ETH_NETWORK: {}", other),
    }
}
