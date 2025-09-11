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
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {Steel, Beacon} from "risc0/steel/Steel.sol";
import {ISecondOpinionOracle} from "./ISecondOpinionOracle.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.
import {Report, IOracleProofReceiver} from "./IOracleProofReceiver.sol";

/// @title LIP-23 Compatible Oracle implemented using RISC Zero
contract SecondOpinionOracle is ISecondOpinionOracle, IOracleProofReceiver {
    /// @notice The journal written by the RISC Zero verifier.
    struct Journal {
        uint256 clBalanceGwei;
        uint256 withdrawalVaultBalanceWei;
        uint256 totalDepositedValidators;
        uint256 totalExitedValidators;
        bytes32 blockRoot;
        Steel.Commitment commitment;
    }

    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable verifier;

    /// @notice The timestamp of the genesis block.
    uint256 public immutable genesis_block_timestamp;

    /// @notice Image ID of the only zkVM guest to accept verification from.
    bytes32 public constant imageId = ImageID.MAINNET_ID;

    /// @notice Seconds per slot
    uint256 public constant SECONDS_PER_SLOT = 12;

    /// @notice Oracle reports stored by refSlot.
    mapping(uint256 => Report) public reports;

    /// @notice Emitted when a new report is stored.
    event ReportUpdated(uint256 refSlot, bytes32 membershipCommitment, uint64 nValidators, Report report);

    /// @notice Initialize the contract, binding it to a specified RISC Zero verifier.
    constructor(IRiscZeroVerifier _verifier, uint256 _genesis_block_timestamp) {
        verifier = _verifier;
        genesis_block_timestamp = _genesis_block_timestamp;
    }

    /// @notice Set an oracle report for a given slot by verifying the ZK proof
    function update(uint256 refSlot, Report calldata r, bytes calldata seal, Steel.Commitment calldata commitment)
        external
    {
        require(Steel.validateCommitment(commitment), "Invalid commitment");

        bytes32 blockRoot = Beacon.parentBlockRoot(_timestampAtSlot(refSlot + 1));

        Journal memory journal = Journal({
            clBalanceGwei: r.clBalanceGwei,
            withdrawalVaultBalanceWei: r.withdrawalVaultBalanceWei,
            totalDepositedValidators: r.totalDepositedValidators,
            totalExitedValidators: r.totalExitedValidators,
            blockRoot: blockRoot,
            commitment: commitment
        });

        verifier.verify(seal, imageId, sha256(abi.encode(journal)));

        // report is now considered valid for the given slot and can be stored
        reports[refSlot] = r;
        emit ReportUpdated(refSlot, r);
    }

    /// @notice Returns the number stored.
    function getReport(uint256 refSlot)
        external
        view
        returns (
            bool success,
            uint256 clBalanceGwei,
            uint256 withdrawalVaultBalanceWei,
            uint256 totalDepositedValidators,
            uint256 totalExitedValidators
        )
    {
        Report memory report = reports[refSlot];
        return (
            report.clBalanceGwei != 0,
            report.clBalanceGwei,
            report.withdrawalVaultBalanceWei,
            report.totalDepositedValidators,
            report.totalExitedValidators
        );
    }

    function _timestampAtSlot(uint256 slot) internal view returns (uint256) {
        return genesis_block_timestamp + slot * SECONDS_PER_SLOT;
    }
}
