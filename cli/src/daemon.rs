use core::panic;

use anyhow::Result;
use boundless_market::{storage::storage_provider_from_env, Client};

use crate::{
    beacon_client::BeaconClient, boundless::build_proof_boundless, build_input, submit_proof,
    Command,
};

pub async fn run_daemon(args: crate::Args, image_id: [u32; 8]) -> Result<()> {
    if let Command::Daemon {
        beacon_rpc_url,
        boundless_config,
        eth_wallet_private_key,
        oracle_contract,
    } = args.command
    {
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
    } else {
        panic!("Invalid command for daemon");
    }
}

fn is_frame_boundary(slot: u64) -> bool {
    const SLOTS_PER_EPOCH: u64 = 32;
    const EPOCHS_PER_FRAME: u64 = 225;
    const SLOTS_PER_FRAME: u64 = SLOTS_PER_EPOCH * EPOCHS_PER_FRAME;
    slot % SLOTS_PER_FRAME == 0
}
