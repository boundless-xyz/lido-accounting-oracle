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

use std::{collections::HashMap, env};

use risc0_build::{embed_methods_with_options, GuestOptionsBuilder};
use risc0_build_ethereum::generate_solidity_files;

// Paths where the generated Solidity files will be written.
const SOLIDITY_IMAGE_ID_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/src/ImageID.sol"
);
const SOLIDITY_ELF_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/tests/Elf.sol");

fn main() {
    let mut guest_features = Vec::new();

    if env::var("CARGO_FEATURE_SKIP_VERIFY").is_ok() {
        guest_features.push("skip-verify".to_string());
    }

    println!(
        "cargo:warning=building guest with features: {:?}",
        guest_features
    );

    // Generate Rust source files for the methods crate.
    let guests = embed_methods_with_options(HashMap::from([(
        "oracle",
        GuestOptionsBuilder::default()
            .features(guest_features)
            .build()
            .unwrap(),
    )]));

    // Generate Solidity source files for use with Forge.
    let solidity_opts = risc0_build_ethereum::Options::default()
        .with_image_id_sol_path(SOLIDITY_IMAGE_ID_PATH)
        .with_elf_sol_path(SOLIDITY_ELF_PATH);

    let _ = generate_solidity_files(guests.as_slice(), &solidity_opts);
}
