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

use alloy::hex::FromHex;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{utils::parse_ether, Address};
use alloy_primitives::{Bytes, U256};
use bitvec::order::Lsb0;
use bitvec::vec::BitVec;
use ethereum_consensus::phase0::presets::mainnet::BeaconBlockHeader;
use ethereum_consensus::ssz::prelude::*;
use lido_oracle_core::input::ProofType;
use lido_oracle_core::soltypes::IOracleProofReceiver;
use lido_oracle_core::{
    generate_oracle_report,
    input::Input,
    mainnet::{WITHDRAWAL_CREDENTIALS, WITHDRAWAL_VAULT_ADDRESS},
    ANVIL_CHAIN_SPEC,
};
use regex::Regex;
use test_utils::{TestStateBuilder, CAPELLA_FORK_SLOT};

use alloy::{
    node_bindings::{Anvil, AnvilInstance},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
};

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
async fn test_initial_and_continuation() -> anyhow::Result<()> {
    let (_anvil, provider, addr) = test_provider().await;

    let prior_membership = {
        let mut b = TestStateBuilder::new(CAPELLA_FORK_SLOT);
        b.with_validators(5);
        b.with_lido_validators(5);
        b.with_validators(3);
        b.with_lido_validators(4);

        let s = b.clone().build();

        let mut block_header = BeaconBlockHeader::default();
        block_header.slot = s.slot();
        block_header.state_root = s.hash_tree_root().unwrap();
        let membership = s
            .validators()
            .iter()
            .map(|v| v.withdrawal_credentials.as_slice() == WITHDRAWAL_CREDENTIALS.as_slice())
            .collect::<BitVec<u32, Lsb0>>();

        let execution_block_root = provider
            .get_block_by_number(1.into())
            .await?
            .unwrap()
            .into_header()
            .hash;

        let input = Input::build(
            &ANVIL_CHAIN_SPEC,
            &block_header,
            &s,
            &execution_block_root,
            &WITHDRAWAL_CREDENTIALS,
            WITHDRAWAL_VAULT_ADDRESS,
            addr,
            BitVec::new(),
            None,
            provider.clone(),
        )
        .await?;
        match input.proof_type {
            ProofType::Initial => {}
            _ => panic!("expected initial proof type"),
        }

        let journal = generate_oracle_report(
            input,
            &ANVIL_CHAIN_SPEC,
            &WITHDRAWAL_CREDENTIALS,
            WITHDRAWAL_VAULT_ADDRESS,
            addr,
        )?;

        assert_eq!(
            journal.report.withdrawalVaultBalanceWei,
            parse_ether("33").unwrap()
        );
        assert_eq!(journal.report.clBalanceGwei, U256::from(10 * 9));

        // submit to the oracle contract
        let res = IOracleProofReceiver::new(addr, &provider)
            .update(s.slot().try_into().unwrap(), journal, Bytes::new())
            .send()
            .await?
            .get_receipt()
            .await?;

        println!("Oracle update tx: {:?}", res);

        membership
    };
    /////////////////////////
    // Test a continuation
    /////////////////////////

    {
        provider.anvil_mine(Some(2), Some(1)).await.unwrap();

        let mut b = TestStateBuilder::new(CAPELLA_FORK_SLOT);
        b.with_validators(5);
        b.with_lido_validators(5);
        b.with_validators(3);
        b.with_lido_validators(4);

        // extra lines
        b.with_lido_validators(1);
        b.with_validators(1);

        let s = b.clone().build();

        let mut block_header = BeaconBlockHeader::default();
        block_header.slot = s.slot();
        block_header.state_root = s.hash_tree_root().unwrap();

        let execution_block_root = provider
            .get_block_by_number(6.into())
            .await?
            .unwrap()
            .into_header()
            .hash;

        let input = Input::build(
            &ANVIL_CHAIN_SPEC,
            &block_header,
            &s,
            &execution_block_root,
            &WITHDRAWAL_CREDENTIALS,
            WITHDRAWAL_VAULT_ADDRESS,
            addr,
            prior_membership,
            Some(5),
            provider.clone(),
        )
        .await?;
        match input.proof_type {
            ProofType::Continuation { .. } => {}
            _ => panic!("expected initial proof type"),
        }
        let journal = generate_oracle_report(
            input,
            &ANVIL_CHAIN_SPEC,
            &WITHDRAWAL_CREDENTIALS,
            WITHDRAWAL_VAULT_ADDRESS,
            addr,
        )?;

        // assert_eq!(
        //     journal.report.withdrawalVaultBalanceWei,
        //     parse_ether("33").unwrap()
        // );
        // assert_eq!(journal.report.clBalanceGwei, U256::from(10 * 9));
    }
    Ok(())
}
