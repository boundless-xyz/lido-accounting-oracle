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

use oracle_builder::MAINNET_ID;

use alloy_primitives::utils::parse_ether;
use ethereum_consensus::phase0::presets::mainnet::BeaconBlockHeader;
use ethereum_consensus::ssz::prelude::*;
use lido_oracle_core::{
    generate_oracle_report,
    input::Input,
    mainnet::{WITHDRAWAL_CREDENTIALS, WITHDRAWAL_VAULT_ADDRESS},
    receipt::DummyReceipt,
    ANVIL_CHAIN_SPEC,
};
use test_utils::{TestStateBuilder, CAPELLA_FORK_SLOT};

use alloy::providers::{ext::AnvilApi, Provider, ProviderBuilder};

/// Returns an Anvil provider the WITHDRAWAL_VAULT_ADDRESS balance set to 33 ether
async fn test_provider() -> impl Provider + Clone {
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.args(["--hardfork", "cancun"]))
        .unwrap();
    let node_info = provider.anvil_node_info().await.unwrap();
    println!("Anvil started: {:?}", node_info);
    provider
        .anvil_set_balance(WITHDRAWAL_VAULT_ADDRESS, parse_ether("33").unwrap())
        .await
        .unwrap();
    // mine a block so the new balance is in the state
    provider.anvil_mine(Some(1), Some(1)).await.unwrap();
    provider
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_initial() -> anyhow::Result<()> {
    let provider = test_provider().await;

    let mut b = TestStateBuilder::new(CAPELLA_FORK_SLOT);
    b.with_validators(5);
    b.with_lido_validators(5);
    b.with_validators(3);
    b.with_lido_validators(4);

    let s = b.build();

    let mut block_header = BeaconBlockHeader::default();
    block_header.slot = s.slot();
    block_header.state_root = s.hash_tree_root().unwrap();

    let execution_block_root = provider
        .get_block_by_number(1.into())
        .await?
        .unwrap()
        .into_header()
        .hash;

    let input = Input::<DummyReceipt>::build_initial(
        &ANVIL_CHAIN_SPEC,
        MAINNET_ID,
        &block_header,
        &s,
        &execution_block_root,
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
        journal.withdrawalVaultBalanceWei,
        parse_ether("33").unwrap()
    );
    assert_eq!(journal.clBalanceGwei, U256::from(10 * 9));

    Ok(())
}

// #[tokio::test]
// async fn test_short_range_continuation() -> anyhow::Result<()> {
//     let n_validators = 10;
//     let n_lido_validators = 1;

//     let provider = test_provider().await;

//     let mut b = TestStateBuilder::new(CAPELLA_FORK_SLOT);
//     b.with_validators(n_validators);
//     b.with_lido_validators(n_lido_validators);
//     let s = b.build();

//     let mut block_header = BeaconBlockHeader::default();
//     block_header.slot = s.slot();
//     block_header.state_root = s.hash_tree_root().unwrap();

//     let input = Input::<DummyReceipt>::build_initial(
//         &ANVIL_CHAIN_SPEC,
//         MAINNET_ID,
//         &block_header,
//         &s,
//         &WITHDRAWAL_CREDENTIALS,
//         WITHDRAWAL_VAULT_ADDRESS,
//         provider.clone(),
//     )
//     .await?;

//     let journal = generate_oracle_report(
//         input,
//         &ANVIL_CHAIN_SPEC,
//         &WITHDRAWAL_CREDENTIALS,
//         WITHDRAWAL_VAULT_ADDRESS,
//     )?;

//     assert_eq!(
//         journal.withdrawalVaultBalanceWei,
//         parse_ether("33").unwrap()
//     );
//     assert_eq!(journal.clBalanceGwei, U256::from(10 * n_lido_validators));

//     let receipt = DummyReceipt::from(journal);

//     let mut b = TestStateBuilder::new(CAPELLA_FORK_SLOT + 1);
//     b.with_validators(n_validators);
//     b.with_lido_validators(n_lido_validators);
//     b.with_prior_state(&s);
//     let s1 = b.build();

//     let mut block_header1 = BeaconBlockHeader::default();
//     block_header1.slot = s1.slot();
//     block_header1.state_root = s1.hash_tree_root().unwrap();

//     let continuation_input = Input::<DummyReceipt>::build_continuation(
//         &ANVIL_CHAIN_SPEC,
//         MAINNET_ID,
//         &block_header1,
//         &s1,
//         &WITHDRAWAL_CREDENTIALS,
//         WITHDRAWAL_VAULT_ADDRESS,
//         &s,
//         receipt,
//         None,
//         provider.clone(),
//     )
//     .await?;

//     let continuation_journal = generate_oracle_report(
//         continuation_input,
//         &ANVIL_CHAIN_SPEC,
//         &WITHDRAWAL_CREDENTIALS,
//         WITHDRAWAL_VAULT_ADDRESS,
//     )?;

//     Ok(())
// }
