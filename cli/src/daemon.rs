use core::panic;

use anyhow::Result;
use boundless_market::{storage::storage_provider_from_env, Client};

use crate::{
    beacon_client::BeaconClient, boundless::build_proof_boundless, build_input, submit_proof, Args,
    Command,
};

pub async fn run_daemon(args: Args, image_id: [u8; 32]) -> Result<()> {
    if let Command::Daemon {
        beacon_rpc_url,
        boundless_config,
        eth_wallet_private_key,
        oracle_contract,
        slots_per_frame,
    } = args.command
    {
        tracing::info!("Starting daemon: polling beacon head");
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
                    let slot = block.message.slot - 1; // This will usually return the first slot of an epoch, so we subtract 1 to get the last slot of the previous epoch
                    tracing::info!("Current beacon finalized slot: {}", slot);
                    if is_frame_boundary(slot, slots_per_frame) {
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

/// Returns true if the given slot is at at the end of a Lido frame
fn is_frame_boundary(slot: u64, slots_per_frame: u64) -> bool {
    (slot + 1) % slots_per_frame == 0
}
