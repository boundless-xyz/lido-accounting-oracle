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

use crate::input::{Input, ProofType};
use crate::soltypes::{Journal, Report, ReportUpdated};
use crate::{error, u64_from_b256, Node};
use alloy_primitives::{Address, U256};
use bitvec::prelude::*;
use bitvec::vec::BitVec;
use risc0_steel::ethereum::EthChainSpec;
use risc0_steel::{Account, Event, SteelVerifier};
use sha2::{Digest, Sha256};
use ssz_multiproofs::ValueIterator;

use crate::error::Result;

pub fn generate_oracle_report(
    input: Input,
    spec: &EthChainSpec,
    withdrawal_credentials: &[u8; 32],
    withdrawal_vault_address: Address,
    oracle_contract_address: Address,
) -> Result<Journal> {
    let Input {
        block_root,
        block_multiproof,
        state_multiproof,
        validators_multiproof,
        evm_input,
        proof_type,
    } = input;

    // obtain the withdrawal vault balance from the EVM input
    let evm_env = evm_input.into_env(spec);
    let account = Account::new(withdrawal_vault_address, &evm_env);
    let withdrawal_vault_balance: U256 = account.info().balance;

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

    let (mut membership, mut num_lido_validators, mut num_exited_validators) = match proof_type {
        ProofType::Initial => (BitVec::<u32, Lsb0>::new(), 0, 0),
        ProofType::Continuation {
            evm_input: cont_evm_input,
            prior_membership,
        } => {
            let cont_evm_env = cont_evm_input.into_env(spec);

            // verify this Steel env using the top level env
            let verifier = SteelVerifier::new(&evm_env);
            verifier.verify(cont_evm_env.commitment());

            // Use the Steel commitment to verify the values we are continuing from
            let event = Event::new::<ReportUpdated>(&cont_evm_env);
            let logs = event.address(oracle_contract_address).query();
            logs.first()
                .map(|e| {
                    assert_eq!(
                        hash_bitvec(&prior_membership),
                        e.membershipCommitment,
                        "prior membership commitment check failed. Does not match the commitment in the journal of the prior proof"
                    );
                    (
                        prior_membership,
                        e.report.totalDepositedValidators.try_into().unwrap(),
                        e.report.totalExitedValidators.try_into().unwrap(),
                    )
                })
                .expect("No matching logs found")
        }
    };

    let n_validators = u64_from_b256(
        validators_multiproof
            .get(gindices::length_gindex())
            .ok_or(error::Error::MissingValue(gindices::length_gindex()))?,
        0,
    );

    // Reserve the capacity for the membership bitvector to save cycles reallocating
    membership.reserve(n_validators.saturating_sub(membership.len() as u64) as usize);

    println!(
        "Computing validator membership for {} validators",
        n_validators
    );
    for validator_index in (membership.len() as u64)..n_validators {
        println!("checking validator {}... ", validator_index);
        let value = validators_values
            .next_assert_gindex(gindices::withdrawal_credentials_gindex(validator_index))?;
        if value == withdrawal_credentials {
            membership.push(true);
            num_lido_validators += 1;
            println!("checking exit epoch for validator {}... ", validator_index);
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
        membershipCommitment: hash_bitvec(&membership).into(),
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

/// Hash a bitvec in a way that includes the bitlength. Just hashing the underlying bytes is not sufficient
/// as any bits above the bitlength would be malleable
fn hash_bitvec(bv: &BitVec<u32>) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Hash bit length first
    hasher.update(&bv.len().to_le_bytes());

    // Access underlying storage directly without cloning
    let raw_slice = bv.as_raw_slice();
    hasher.update(bytemuck::cast_slice(raw_slice));

    hasher.finalize().into()
}
