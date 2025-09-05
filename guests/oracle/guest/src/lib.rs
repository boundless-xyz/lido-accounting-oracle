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

use alloy_primitives::Address;
use alloy_sol_types::SolValue;
use bincode::deserialize;
use lido_oracle_core::{generate_oracle_report, input::Input};
use risc0_steel::ethereum::EthChainSpec;
use risc0_zkvm::{guest::env, Receipt};

pub fn entry(
    spec: &EthChainSpec,
    withdrawal_credentials: &[u8; 32],
    withdrawal_vault_address: Address,
) {
    env::log("Reading input");
    let input_bytes = env::read_frame();

    env::log("Deserializing input");
    let input: Input<Receipt> = deserialize(&input_bytes).expect("Failed to deserialize input");

    let journal = generate_oracle_report(
        input,
        spec,
        withdrawal_credentials,
        withdrawal_vault_address,
    )
    .expect("Failed to Generate oracle report");

    env::log("Writing journal");
    env::commit_slice(&journal.abi_encode());
}
