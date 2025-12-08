use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{utils::parse_ether, U256};
use anyhow::Result;
use boundless_market::{
    request_builder::OfferParams, Client, Deployment, GuestEnv, StorageProviderConfig,
};
use clap::Parser;
use lido_oracle_core::Input;
use url::Url;

use crate::Proof;

/// Configuration specific to using Boundles as the proof provider
#[derive(Parser, Debug)]
pub struct BoundlessConfig {
    #[clap(long, env)]
    pub boundless_rpc_url: Url,

    #[clap(long, env)]
    pub boundless_private_key: PrivateKeySigner,

    /// URL that points to the oracle zkVM image
    #[clap(long, env)]
    pub image_url: Url,

    /// ETH threshold for submitting new requests.
    #[clap(long, value_parser = parse_ether, default_value = "0.01")]
    pub eth_threshold: U256,

    /// Maximum ETH price for requests.
    #[clap(long, value_parser = parse_ether, default_value = "0.1")]
    pub max_eth_price: U256,

    /// Lock collateral in raw value.
    ///
    /// Default value is 1 ZKC
    #[clap(long, default_value = "1000000000000000000")]
    pub lock_collateral: U256,

    /// Ramp up period in seconds.
    #[clap(long, default_value = "180")]
    pub ramp_up_period: u32,

    /// Lock timeout in seconds.
    #[clap(long, default_value = "300")]
    pub lock_timeout: u32,

    /// Request timeout in seconds.
    #[clap(long, default_value = "600")]
    pub timeout: u32,

    /// Status check interval in seconds. Checks the status of the previously submitted requests.
    #[clap(long, default_value = "20")]
    pub status_check_interval: u64,

    /// Maximum retry attempts for failed requests.
    #[clap(long, default_value = "3")]
    pub max_retries: u32,

    /// Storage provider configuration to use for Boundless
    /// See https://docs.boundless.network/developers/tutorials/request#storage-providers
    #[clap(flatten, next_help_heading = "Storage Provider")]
    pub storage_config: StorageProviderConfig,

    /// Deployment of the Boundless contracts and services to use.
    ///
    /// Will be automatically resolved from the connected chain ID if unspecified.
    #[clap(flatten, next_help_heading = "Boundless Market Deployment")]
    pub deployment: Option<Deployment>,
}

pub async fn build_proof_boundless<'a>(
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
                .max_price(boundless_config.max_eth_price)
                .timeout(boundless_config.timeout)
                .lock_timeout(boundless_config.lock_timeout)
                .ramp_up_period(boundless_config.ramp_up_period),
        );

    let (request_id, expires_at) = boundless_client.submit_onchain(request).await?;

    let mut attempts = 0;
    while attempts < boundless_config.max_retries {
        match boundless_client
            .wait_for_request_fulfillment(
                request_id,
                Duration::from_secs(boundless_config.status_check_interval),
                expires_at,
            )
            .await
        {
            Ok(fulfillment) => {
                tracing::info!("Request {:x} fulfilled", request_id);

                return Ok(Proof {
                    slot,
                    journal: fulfillment
                        .data()?
                        .journal()
                        .expect("missing journal")
                        .clone(),
                    seal: fulfillment.seal,
                });
            }
            Err(e) => {
                attempts += 1;
                tracing::warn!(
                    "Error checking status for request {:x} (attempt {}/{}): {}",
                    request_id,
                    attempts,
                    boundless_config.max_retries,
                    e
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(boundless_config.status_check_interval)).await;
    }
    return Err(anyhow::anyhow!(
        "Failed to fulfill request {:x} after {} attempts",
        request_id,
        boundless_config.max_retries
    ));
}
