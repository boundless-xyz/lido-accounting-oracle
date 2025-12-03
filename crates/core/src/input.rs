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

#[cfg(feature = "builder")]
use risc0_steel::beacon::BeaconCommit;
use risc0_steel::ethereum::EthEvmInput;
use ssz_multiproofs::Multiproof;
#[cfg(feature = "builder")]
use {
    crate::build_with_versioned_state,
    crate::eip4788::{self, Eip4788Call},
    crate::Result,
    alloy_primitives::{Address, B256},
    alloy_sol_types::SolCall,
    beacon_state::mainnet::BeaconState,
    bitvec::prelude::*,
    ethereum_consensus::phase0::BeaconBlockHeader,
    risc0_steel::{
        alloy::{network::Ethereum, providers::Provider},
        ethereum::EthEvmEnv,
        host::db::{ProofDb, ProviderDb},
        host::HostCommit,
        Account, Contract,
    },
    ssz_multiproofs::MultiproofBuilder,
    ssz_rs::prelude::*,
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Input<'a> {
    /// Steel EvmInput, used for reading the withdrawal vault balance and block_root
    /// This is the root of all trusts in the oracle
    pub evm_input: EthEvmInput,

    /// Timestamp that can be used to retrieve the block root from EIP-4788
    /// This block root will be used to verify the block multiproof
    pub header_timestamp: u64,

    /// Merkle SSZ proof rooted in the beacon block
    #[serde(borrow)]
    pub block_multiproof: Multiproof<'a>,

    /// Merkle SSZ proof rooted in the beacon state
    #[serde(borrow)]
    pub state_multiproof: Multiproof<'a>,

    /// Used fields of the active validators
    #[serde(borrow)]
    pub validators_multiproof: Multiproof<'a>,
}

#[cfg(feature = "builder")]
impl<'a> Input<'a> {
    /// Build an oracle proof for all validators in the beacon state
    pub async fn build_blockhash_commit<P>(
        env: EthEvmEnv<ProofDb<ProviderDb<Ethereum, P>>, HostCommit<()>>,
        block_header: &BeaconBlockHeader,
        beacon_state: &BeaconState,
        withdrawal_credentials: &B256,
        withdrawal_vault_address: Address,
    ) -> Result<Self>
    where
        P: Provider + 'static + Clone,
    {
        let (header_timestamp, block_multiproof, state_multiproof, validators_multiproof, env) =
            Self::build(
                env,
                block_header,
                beacon_state,
                withdrawal_credentials,
                withdrawal_vault_address,
            )
            .await?;

        Ok(Self {
            header_timestamp,
            block_multiproof,
            state_multiproof,
            validators_multiproof,
            evm_input: env.into_input().await.unwrap(),
        })
    }

    /// Build an oracle proof for all validators in the beacon state
    pub async fn build_beacon_commit<P>(
        env: EthEvmEnv<ProofDb<ProviderDb<Ethereum, P>>, HostCommit<BeaconCommit>>,
        block_header: &BeaconBlockHeader,
        beacon_state: &BeaconState,
        withdrawal_credentials: &B256,
        withdrawal_vault_address: Address,
    ) -> Result<Self>
    where
        P: Provider + 'static + Clone,
    {
        let (header_timestamp, block_multiproof, state_multiproof, validators_multiproof, env) =
            Self::build(
                env,
                block_header,
                beacon_state,
                withdrawal_credentials,
                withdrawal_vault_address,
            )
            .await?;

        Ok(Self {
            header_timestamp,
            block_multiproof,
            state_multiproof,
            validators_multiproof,
            evm_input: env.into_input().await.unwrap(),
        })
    }

    /// Build an oracle proof for all validators in the beacon state
    pub async fn build<P, C>(
        mut env: EthEvmEnv<ProofDb<ProviderDb<Ethereum, P>>, HostCommit<C>>,
        block_header: &BeaconBlockHeader,
        beacon_state: &BeaconState,
        withdrawal_credentials: &B256,
        withdrawal_vault_address: Address,
    ) -> Result<(
        u64,
        Multiproof<'a>,
        Multiproof<'a>,
        Multiproof<'a>,
        EthEvmEnv<ProofDb<ProviderDb<Ethereum, P>>, HostCommit<C>>,
    )>
    where
        P: Provider + 'static + Clone,
    {
        let header_timestamp = env.header().timestamp;

        let withdrawal_vault = {
            let account = Account::preflight(withdrawal_vault_address, &mut env);
            account.bytecode(true).info().await.unwrap()
        };
        tracing::info!("withdrawal_vault balance: {}", withdrawal_vault.balance);

        let block_root = {
            let call = Eip4788Call::new((U256::from(header_timestamp),));
            let mut contract = Contract::preflight(eip4788::ADDRESS, &mut env);
            contract.call_builder(&call).call().await.unwrap()
        };

        // sanity check that the computed block root matches the retrieved root
        assert_eq!(
            block_header.hash_tree_root()?,
            block_root,
            "Computed block root does not match EIP-4788 retrieved root"
        );

        let membership = beacon_state
            .validators()
            .iter()
            .map(|v| v.withdrawal_credentials.as_slice() == withdrawal_credentials.as_slice())
            .collect::<BitVec<u32, Lsb0>>();

        let block_multiproof = MultiproofBuilder::new()
            .with_gindex(gindices::block_slot_gindex().try_into()?)
            .with_gindex(gindices::state_root_gindex().try_into()?)
            .build(block_header)?;

        let state_multiproof_builder = MultiproofBuilder::new()
            .with_gindex(gindices::validators_gindex().try_into()?)
            .with_gindices(membership.iter_ones().map(|i| {
                gindices::validator_balance_gindex(i as u64)
                    .try_into()
                    .unwrap()
            }));
        let state_multiproof = build_with_versioned_state(state_multiproof_builder, &beacon_state)?;

        let validators_multiproof = MultiproofBuilder::new()
            .with_gindex(gindices::length_gindex().try_into()?)
            .with_gindices((0..beacon_state.validators().len()).map(|i| {
                tracing::debug!("Including validator {}", i);
                gindices::withdrawal_credentials_gindex(i as u64)
                    .try_into()
                    .unwrap()
            }))
            .with_gindices(membership.iter_ones().map(|i| {
                tracing::debug!("Including exit epoch for validator {}", i);
                gindices::exit_epoch_gindex(i as u64).try_into().unwrap()
            }))
            .build(beacon_state.validators())?;

        Ok((
            header_timestamp,
            block_multiproof,
            state_multiproof,
            validators_multiproof,
            env,
        ))
    }
}
