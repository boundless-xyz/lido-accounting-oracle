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

use alloy_primitives::B256;
use bitvec::prelude::*;
#[cfg(feature = "builder")]
use risc0_steel::alloy::providers::Provider;
#[cfg(feature = "builder")]
use risc0_steel::ethereum::EthChainSpec;
use risc0_steel::ethereum::EthEvmInput;
use ssz_multiproofs::Multiproof;

#[cfg(feature = "builder")]
use {
    crate::build_with_versioned_state,
    crate::soltypes::ReportUpdated,
    crate::Result,
    alloy_primitives::Address,
    beacon_state::mainnet::BeaconState,
    ethereum_consensus::phase0::BeaconBlockHeader,
    risc0_steel::{ethereum::EthEvmEnv, Account, Event},
    ssz_multiproofs::MultiproofBuilder,
    ssz_rs::prelude::*,
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Input<'a> {
    /// Block that the proof is rooted in
    pub block_root: B256,

    /// Merkle SSZ proof rooted in the beacon block
    #[serde(borrow)]
    pub block_multiproof: Multiproof<'a>,

    /// Merkle SSZ proof rooted in the beacon state
    #[serde(borrow)]
    pub state_multiproof: Multiproof<'a>,

    /// Used fields of the active validators
    #[serde(borrow)]
    pub validators_multiproof: Multiproof<'a>,

    /// Steel EvmInput, used for reading the withdrawal vault balance
    pub evm_input: EthEvmInput,

    /// If this proof is a continuation, the membership status of the validators
    pub proof_type: ProofType,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum ProofType {
    Initial,
    Continuation {
        /// EVM Input for the block where the prior report was made
        evm_input: EthEvmInput,
        /// The prior membership bitfield for the previous proof. This will be checked using the Steel to find a prior
        /// submission that produces this membership
        prior_membership: BitVec<u32, Lsb0>,
    },
}

#[cfg(feature = "builder")]
impl<'a> Input<'a> {
    /// Build an oracle proof for all validators in the beacon state
    pub async fn build<P>(
        spec: &EthChainSpec,
        block_header: &BeaconBlockHeader,
        beacon_state: &BeaconState,
        execution_block_hash: &B256,
        withdrawal_credentials: &B256,
        withdrawal_vault_address: Address,
        oracle_address: Address,
        prior_membership: BitVec<u32, Lsb0>,
        prior_report_block: Option<u64>,
        provider: P,
    ) -> Result<Self>
    where
        P: Provider + 'static + Clone,
    {
        // build the Steel input for reading the balance
        let mut env = EthEvmEnv::builder()
            .provider(provider.clone())
            .chain_spec(&spec)
            .block_hash(*execution_block_hash)
            .build()
            .await
            .unwrap();
        let _preflight_info = {
            let account = Account::preflight(withdrawal_vault_address, &mut env);
            account.bytecode(true).info().await.unwrap()
        };

        tracing::info!("withdrawal_vault balance: {}", _preflight_info.balance);

        let block_root = block_header.hash_tree_root()?;

        let membership = beacon_state
            .validators()
            .iter()
            .map(|v| v.withdrawal_credentials.as_slice() == withdrawal_credentials.as_slice())
            .collect::<BitVec<u32, Lsb0>>();

        let start_index = prior_membership.len();
        // sanity check
        assert_eq!(
            membership[0..start_index],
            prior_membership,
            "prior membership is not a prefix for the membership retrieved from the beacon state"
        );

        let proof_type = match prior_report_block {
            Some(block) => {
                use risc0_steel::SteelVerifier;

                let mut prior_env = EthEvmEnv::builder()
                    .provider(provider)
                    .chain_spec(&spec)
                    .block_number(block)
                    .build()
                    .await
                    .unwrap();
                let event = Event::preflight::<ReportUpdated>(&mut prior_env);
                let logs = event.address(oracle_address).query().await.unwrap();
                assert!(
                    !logs.is_empty(),
                    "no prior ReportUpdated events found for the given oracle address"
                );
                let commitment = prior_env.commitment();
                let evm_input = prior_env.into_input().await.unwrap();

                // Preflight verificiation of this commitment with the top level env
                SteelVerifier::preflight(&mut env)
                    .verify(&commitment)
                    .await
                    .unwrap();

                ProofType::Continuation {
                    evm_input,
                    prior_membership,
                }
            }
            None => ProofType::Initial,
        };

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
            .with_gindices((start_index..beacon_state.validators().len()).map(|i| {
                println!("Including validator {}", i);
                gindices::withdrawal_credentials_gindex(i as u64)
                    .try_into()
                    .unwrap()
            }))
            .with_gindices(
                membership
                    .iter_ones()
                    .filter(|i| i >= &start_index)
                    .map(|i| {
                        println!("Including exit epoch for validator {}", i);
                        gindices::exit_epoch_gindex(i as u64).try_into().unwrap()
                    }),
            )
            .build(beacon_state.validators())?;

        Ok(Self {
            proof_type,
            block_root,
            block_multiproof,
            state_multiproof,
            validators_multiproof,
            evm_input: env.into_input().await.unwrap(),
        })
    }
}
