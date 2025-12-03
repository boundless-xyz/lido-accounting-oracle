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

use crate::eip4788::{self, Eip4788Call};
use crate::input::Input;
use crate::soltypes::{Journal, Report};
use crate::{error, u64_from_b256, Node};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use bitvec::prelude::*;
use bitvec::vec::BitVec;
use risc0_steel::ethereum::EthChainSpec;
use risc0_steel::{Account, Contract};
use ssz_multiproofs::ValueIterator;

use crate::error::Result;

pub fn generate_oracle_report(
    input: Input,
    spec: &EthChainSpec,
    withdrawal_credentials: &[u8; 32],
    withdrawal_vault_address: Address,
) -> Result<Journal> {
    let Input {
        header_timestamp,
        block_multiproof,
        state_multiproof,
        validators_multiproof,
        evm_input,
    } = input;
    let evm_env = evm_input.into_env(spec);

    // obtain the withdrawal vault balance from the EVM input
    let account = Account::new(withdrawal_vault_address, &evm_env);
    let withdrawal_vault_balance: U256 = account.info().balance;

    // Obtain the block_root using EIP-4788 call
    // indexed by header_timestamp
    let eip4788_contract = Contract::new(eip4788::ADDRESS, &evm_env);
    let call = Eip4788Call::new((U256::from(header_timestamp),));
    let block_root = eip4788_contract.call_builder(&call).call();

    tracing::info!("Verifying block multiproof");
    block_multiproof.verify(&block_root)?;
    let mut block_values = block_multiproof.values();

    let slot = u64_from_b256(
        block_values.next_assert_gindex(gindices::block_slot_gindex())?,
        0,
    );
    let state_root = block_values.next_assert_gindex(gindices::state_root_gindex())?;
    let current_epoch = slot / 32;

    tracing::info!("Verifying state multiproof");
    state_multiproof.verify(&state_root)?;
    let mut state_values = state_multiproof.values();
    let validators_root = state_values.next_assert_gindex(gindices::validators_gindex())?;

    tracing::info!("Verifying validators multiproof");
    validators_multiproof.verify(&validators_root)?;
    let mut validators_values = validators_multiproof.values();

    let (mut membership, mut num_lido_validators, mut num_exited_validators) =
        (BitVec::<u32, Lsb0>::new(), 0, 0);

    let n_validators = u64_from_b256(
        validators_multiproof
            .get(gindices::length_gindex())
            .ok_or(error::Error::MissingValue(gindices::length_gindex()))?,
        0,
    );

    // Reserve the capacity for the membership bitvector to save cycles reallocating
    membership.reserve(n_validators.saturating_sub(membership.len() as u64) as usize);

    tracing::debug!(
        "Computing validator membership for {} validators",
        n_validators
    );
    for validator_index in (membership.len() as u64)..n_validators {
        tracing::debug!("checking validator {}... ", validator_index);
        let value = validators_values
            .next_assert_gindex(gindices::withdrawal_credentials_gindex(validator_index))?;
        if value == withdrawal_credentials {
            membership.push(true);
            num_lido_validators += 1;
            tracing::debug!("checking exit epoch for validator {}... ", validator_index);
            let exit_epoch = validators_values
                .next_assert_gindex(gindices::exit_epoch_gindex(validator_index))?;
            if u64_from_b256(&exit_epoch, 0) <= current_epoch {
                num_exited_validators += 1;
            }
        } else {
            membership.push(false);
        }
    }

    // cannot update this from a prior proof as balances can change
    let cl_balance = accumulate_balances(&mut state_values, &membership);

    // Commit the journal
    let journal = Journal {
        refSlot: U256::from(slot),
        report: Report {
            clBalanceGwei: U256::from(cl_balance),
            withdrawalVaultBalanceWei: withdrawal_vault_balance.into(),
            totalDepositedValidators: U256::from(num_lido_validators),
            totalExitedValidators: U256::from(num_exited_validators),
        },
        blockRoot: block_root,
        commitment: evm_env.into_commitment().into(),
    };

    Ok(journal)
}

fn accumulate_balances<'a, I: Iterator<Item = (u64, &'a Node)>>(
    values: &mut ValueIterator<'a, I, 32>,
    membership: &BitVec<u32, Lsb0>,
) -> u64 {
    // accumulate the balances but iterating over the membership bitvec
    // Multiple balances are packed into a single gindex so this cannot be a straight iteration
    let mut cl_balance = 0;
    let mut current_leaf = (0, &[0_u8; 32]); // 0 is an invalid gindex so this will always be updated on the first validator
    for validator_index in membership.iter_ones() {
        let expeted_gindex = gindices::validator_balance_gindex(validator_index as u64);
        if current_leaf.0 != expeted_gindex {
            current_leaf = values.next().expect(&format!(
                "Missing valdator {} balance value in multiproof",
                validator_index,
            ));
        }
        assert_eq!(current_leaf.0, expeted_gindex);
        let balance = u64_from_b256(&current_leaf.1, validator_index as usize % 4);
        cl_balance += balance;
    }
    cl_balance
}
