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
use risc0_zkvm::Digest;
use ssz_multiproofs::Multiproof;

#[cfg(feature = "builder")]
use {
    crate::build_with_versioned_state,
    crate::{Error, Result},
    alloy_primitives::Address,
    beacon_state::mainnet::BeaconState,
    ethereum_consensus::deneb::mainnet::HistoricalBatch,
    ethereum_consensus::phase0::BeaconBlockHeader,
    risc0_steel::ethereum::EthEvmEnv,
    risc0_steel::Account,
    ssz_multiproofs::MultiproofBuilder,
    ssz_rs::prelude::*,
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Input<'a, R> {
    /// The Program ID of this program. Need to accept it as input rather than hard-code otherwise it creates a cyclic hash reference
    /// This MUST be written to the journal and checked by the verifier! See https://github.com/risc0/risc0-ethereum/blob/main/contracts/src/RiscZeroSetVerifier.sol#L114
    pub self_program_id: Digest,

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
    #[serde(borrow)]
    pub proof_type: ProofType<'a, R>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ProofType<'a, R> {
    Initial,
    Continuation {
        #[serde(borrow)]
        cont_type: ContinuationType<'a>,
        /// Journal to verify the previous proof
        prior_receipt: R,
        /// The prior membership bitfield for the previous proof to be checked against the journal membershipCommitment
        prior_membership: BitVec<u32, Lsb0>,
        /// The slot of the prior proof
        prior_slot: u64,
        /// The state root of the prior proof
        prior_state_root: B256,
    },
}

/// Continuations proofs are slightly different depending on how far back the prior proof is.
/// There are two possibilities here. Either
/// 1. prior_slot < slot <= prior_slot + SLOTS_PER_HISTORICAL_ROOT
///    Prove the prior state root is in the state_roots list of the current state at (prior_slot % SLOTS_PER_HISTORICAL_ROOT)
/// 2. slot > prior_slot + SLOTS_PER_HISTORICAL_ROOT
///     This requires doing an extra step. In this case prove an entry in the historical_summaries list of the current state
///     and then prove the prior state root is in the state_roots list of the historical summary.
///    The element in the historical_summaries list is at index (prior_slot - CAPELLA_FORK_SLOT) / SLOTS_PER_HISTORICAL_ROOT
///    and the index in the state_roots list is (prior_slot % SLOTS_PER_HISTORICAL_ROOT).
///    This also requires fetching the state at slot ( (prior_slot / SLOTS_PER_HISTORICAL_ROOT + 1) * SLOTS_PER_HISTORICAL_ROOT )
///    to retrieve its state_roots list and build a merkle proof into it
///
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ContinuationType<'a> {
    ShortRange,
    LongRange {
        /// The historical summary multiproof to verify the historical summary root
        #[serde(borrow)]
        hist_summary_multiproof: Multiproof<'a>,
    },
}

#[cfg(feature = "builder")]
impl<'a, R> Input<'a, R> {
    /// Build an oracle proof for all validators in the beacon state
    pub async fn build_initial<D, P>(
        spec: &EthChainSpec,
        self_program_id: D,
        block_header: &BeaconBlockHeader,
        beacon_state: &BeaconState,
        withdrawal_credentials: &B256,
        withdrawal_vault_address: Address,
        provider: P,
    ) -> Result<Self>
    where
        D: Into<Digest>,
        P: Provider + 'static,
    {
        use risc0_steel::ethereum::EthEvmEnv;

        let block_root = block_header.hash_tree_root()?;

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
                gindices::withdrawal_credentials_gindex(i as u64)
                    .try_into()
                    .unwrap()
            }))
            .with_gindices(
                membership
                    .iter_ones()
                    .map(|i| gindices::exit_epoch_gindex(i as u64).try_into().unwrap()),
            )
            .build(beacon_state.validators())?;

        // build the Steel input for reading the balance
        let mut env = EthEvmEnv::builder()
            .provider(provider)
            .chain_spec(&spec)
            .build()
            .await
            .unwrap();
        let _preflight_info = {
            let account = Account::preflight(withdrawal_vault_address, &mut env);
            account.bytecode(true).info().await.unwrap()
        };
        let evm_input = env.into_input().await.unwrap();

        Ok(Self {
            self_program_id: self_program_id.into(),
            proof_type: ProofType::Initial,
            block_root,
            block_multiproof,
            state_multiproof,
            validators_multiproof,
            evm_input,
        })
    }
}
