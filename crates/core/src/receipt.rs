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

use crate::{Error, Journal, Result};
use alloy_sol_types::SolType;
use risc0_zkvm::Digest;

pub trait Receipt {
    fn verify(&self, image_id: impl Into<Digest>) -> Result<()>;
    fn journal(&self) -> Result<Journal>;
}

impl Receipt for risc0_zkvm::Receipt {
    fn verify(&self, image_id: impl Into<Digest>) -> Result<()> {
        self.verify(image_id.into())
            .map_err(|e| Error::ReceiptVerification(e.to_string()))
    }

    fn journal(&self) -> Result<Journal> {
        Journal::abi_decode(&self.journal.bytes).map_err(|e| Error::JournalDecoding(e.to_string()))
    }
}

/// A "receipt" used in testing where proofs are not available
pub struct DummyReceipt(Journal);

impl Receipt for DummyReceipt {
    fn verify(&self, _image_id: impl Into<Digest>) -> Result<()> {
        Ok(())
    }

    fn journal(&self) -> Result<Journal> {
        Ok(self.0.clone())
    }
}

impl From<Journal> for DummyReceipt {
    fn from(journal: Journal) -> Self {
        DummyReceipt(journal)
    }
}
