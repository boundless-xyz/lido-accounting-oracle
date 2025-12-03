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

use alloy_sol_types::sol;

sol! {
    #[derive(Debug)]
    struct Commitment {
        uint256 id;
        bytes32 digest;
        bytes32 configID;
    }

    #[derive(Debug)]
    struct Journal {
        uint256 refSlot;
        Report report;
        bytes32 blockRoot;
        Commitment commitment;
    }

    #[derive(Debug)]
    struct Report {
        uint256 clBalanceGwei;
        uint256 withdrawalVaultBalanceWei;
        uint256 totalDepositedValidators;
        uint256 totalExitedValidators;
    }

    #[sol(rpc)]
    contract IBoundlessMarketCallback {
        function handleProof(bytes32 imageId, bytes calldata journalBytes, bytes calldata seal) external;
    }

    event ReportUpdated(uint256 refSlot, bytes32 membershipCommitment, Report report);
}

impl From<risc0_steel::Commitment> for Commitment {
    fn from(c: risc0_steel::Commitment) -> Self {
        Commitment {
            id: c.id.into(),
            digest: c.digest.into(),
            configID: c.configID.into(),
        }
    }
}
