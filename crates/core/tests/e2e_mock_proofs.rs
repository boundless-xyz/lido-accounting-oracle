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

use std::process::Command;
use std::str::FromStr;

use alloy::eips::BlockId;
use alloy::hex::FromHex;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::{
    node_bindings::{Anvil, AnvilInstance},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
};
use alloy_primitives::{address, Bytes, B256, U256};
use alloy_primitives::{utils::parse_ether, Address};
use alloy_sol_types::SolValue;
use ethereum_consensus::phase0::presets::mainnet::BeaconBlockHeader;
use ethereum_consensus::ssz::prelude::*;
use lido_oracle_core::eip4788::{ADDRESS as BLOCK_ROOTS_ADDRESS, CODE, HISTORY_BUFFER_LENGTH};
use lido_oracle_core::soltypes::IBoundlessMarketCallback;
use lido_oracle_core::{
    generate_oracle_report,
    input::Input,
    mainnet::{WITHDRAWAL_CREDENTIALS, WITHDRAWAL_VAULT_ADDRESS},
    ANVIL_CHAIN_SPEC,
};
use oracle_builder::MAINNET_ID;
use regex::Regex;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::ReceiptClaim;
use serde_json::json;
use test_utils::{TestStateBuilder, CAPELLA_FORK_SLOT};

const SYSTEM_ADDRESS: Address = address!("fffffffffffffffffffffffffffffffffffffffe");

/// Returns an Anvil provider the oracle contracts deployed and the WITHDRAWAL_VAULT_ADDRESS balance set to 33 ether
async fn test_provider() -> (AnvilInstance, impl Provider + Clone, Address) {
    // Launch Anvil with desired args
    let anvil = Anvil::new().args(["--hardfork", "cancun"]).spawn();

    // Get the RPC URL
    let rpc_url = anvil.endpoint();
    println!("Anvil RPC running at: {}", rpc_url);

    let private_key = format!("0x{}", hex::encode(anvil.keys()[0].to_bytes()));
    let signer = PrivateKeySigner::from_str(&private_key).unwrap();

    // Build provider against that URL
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(rpc_url.parse().unwrap());
    let node_info = provider.anvil_node_info().await.unwrap();
    println!("Anvil started: {:?}", node_info);

    // Deploy the EIP-4788 contract code at the expected address
    provider
        .anvil_set_code(BLOCK_ROOTS_ADDRESS, Bytes::copy_from_slice(&CODE))
        .await
        .unwrap();

    // Set the balance of the WITHDRAWAL_VAULT_ADDRESS to 33 ether
    provider
        .anvil_set_balance(WITHDRAWAL_VAULT_ADDRESS, parse_ether("33").unwrap())
        .await
        .unwrap();

    // deploy the Oracle contracts using the deploy script
    let output = Command::new("forge")
        .current_dir("../../contracts/")
        .env("RISC0_DEV_MODE", "1")
        .env("ETH_WALLET_PRIVATE_KEY", &private_key)
        .args([
            "script",
            "./script/Deploy.s.sol:Deploy",
            "--rpc-url",
            &rpc_url,
            "--broadcast",
            "-vvvv",
        ])
        .output()
        .expect("failed to execute forge script");

    // mine a block to force awaiting for the above to finalize
    provider.anvil_mine(Some(1), Some(1)).await.unwrap();

    // Regex: captures lines like 'Deployed <ContractName> to <Address>'
    let re = Regex::new(r"Deployed SecondOpinionOracle to (0x[0-9a-fA-F]{40})").unwrap();

    let addr = Address::from_hex(
        re.captures_iter(&String::from_utf8_lossy(&output.stdout))
            .next()
            .expect(
                "could not find deployed contract address of SecondOpinionOracle in forge output",
            )[1]
        .to_string(),
    )
    .unwrap();

    println!("Deployed contract: {}", addr);

    (anvil, provider, addr)
}

#[tokio::test]
async fn test_submit_report() -> anyhow::Result<()> {
    let (_anvil, provider, addr) = test_provider().await;

    let mut b = TestStateBuilder::new(CAPELLA_FORK_SLOT);
    b.with_validators(5);
    b.with_lido_validators(5);
    b.with_validators(3);
    b.with_lido_validators(4);

    let s = b.clone().build();

    let mut block_header = BeaconBlockHeader::default();
    block_header.slot = s.slot();
    block_header.state_root = s.hash_tree_root().unwrap();

    // Store this block in the EIP-4788 contract storage for the input builder to reference
    let block_root = block_header.hash_tree_root().unwrap();
    set_eip4788_beacon_root(&provider, block_root).await?;

    let execution_block_header = provider
        .get_block(BlockId::latest())
        .await?
        .unwrap()
        .into_header();

    let input = Input::build(
        &ANVIL_CHAIN_SPEC,
        &block_header,
        &s,
        &execution_block_header.hash,
        &WITHDRAWAL_CREDENTIALS,
        WITHDRAWAL_VAULT_ADDRESS,
        provider.clone(),
    )
    .await?;

    let journal = generate_oracle_report(
        input,
        &ANVIL_CHAIN_SPEC,
        &WITHDRAWAL_CREDENTIALS,
        WITHDRAWAL_VAULT_ADDRESS,
    )?;

    assert_eq!(
        journal.report.withdrawalVaultBalanceWei,
        parse_ether("33").unwrap()
    );
    assert_eq!(journal.report.clBalanceGwei, U256::from(10 * 9));

    let journal_bytes = journal.abi_encode();
    let seal = mock_prove(MAINNET_ID, journal_bytes.clone());

    // submit to the oracle contract
    let res = IBoundlessMarketCallback::new(addr, &provider)
        .handleProof(
            B256::from_slice(bytemuck::cast_slice(&MAINNET_ID[..])),
            journal_bytes.into(),
            seal,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("Oracle update tx: {:?}", res);

    Ok(())
}

// This is the selector for the test verifier that indicates a mock proof
const SELECTOR: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

/// Construct a mock seal for the given image ID and journal that will verify with the MockVerifier contract
fn mock_prove(image_id: [u32; 8], journal_bytes: Vec<u8>) -> Bytes {
    let claim_digest = ReceiptClaim::ok(image_id, journal_bytes).digest();
    mock_prove_claim(claim_digest.as_bytes().try_into().unwrap())
}

/// Construct a mock receipt for the given claim digest.
/// The returned Receipt.seal is SELECTOR || claim_digest.
fn mock_prove_claim(claim_digest: B256) -> Bytes {
    let mut buf = Vec::with_capacity(SELECTOR.len() + 32);
    buf.extend_from_slice(&SELECTOR);
    buf.extend_from_slice(claim_digest.as_slice()); // B256 -> &[u8;32]
    Bytes::from(buf)
}

/// This manually performs the operation done automatically by block producers since EIP-4788
/// It impersonates the SYSTEM_ADDRESS to call the EIP-4788 contract and set the block root
/// for the current block timestamp.
/// This disables automining so this function can be called and then the block root used in a transaction in the same block.
async fn set_eip4788_beacon_root(
    provider: &impl Provider,
    beacon_block_root: B256,
) -> anyhow::Result<()> {
    provider.anvil_set_auto_mine(false).await.unwrap();
    provider
        .anvil_impersonate_account(SYSTEM_ADDRESS)
        .await
        .unwrap();

    // Set the balance of the SYSTEM_ADDRESS to 1 ether
    provider
        .anvil_set_balance(SYSTEM_ADDRESS, parse_ether("1").unwrap())
        .await
        .unwrap();

    // Create the tx from SYSTEM to update the EIP-4788 contract
    let tx = TransactionRequest::default()
        .from(SYSTEM_ADDRESS)
        .to(BLOCK_ROOTS_ADDRESS)
        .input(Bytes::copy_from_slice(beacon_block_root.as_slice()).into())
        .gas_limit(100_000u64)
        .max_fee_per_gas(1_000_000_000) // 1 gwei
        .max_priority_fee_per_gas(1_000_000_000); // 1 gwei

    let _tx_hash: B256 = provider
        .raw_request("eth_sendTransaction".into(), json!([tx]))
        .await?;

    // progress the block so the state is committed in the header
    provider
        .anvil_stop_impersonating_account(SYSTEM_ADDRESS)
        .await
        .unwrap();
    provider.anvil_set_auto_mine(true).await.unwrap();

    Ok(())
}
