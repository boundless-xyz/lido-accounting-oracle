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
import {ITestVerifier} from "./ITestVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.
import {TestReport} from "./ITestVerifier.sol";

/// @title LIP-23 Compatible Oracle implemented using RISC Zero
contract TestVerifier is ITestVerifier {
    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable verifier;

    /// @notice Image ID of the only zkVM guest to accept verification from.
    bytes32 public constant IMAGE_ID = ImageID.MAINNET_ID;

    /// @notice Initialize the contract, binding it to a specified RISC Zero verifier.
    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
    }

    /// @notice This accepts the blockroot directly so is useful for testing on devnets where
    /// the beacon block root is undefined
    function verify(bytes32 blockRoot, TestReport calldata r, bytes calldata seal) public view {
        bytes memory journal = abi.encodePacked(
            blockRoot, r.clBalanceGwei, r.withdrawalVaultBalanceWei, r.totalDepositedValidators, r.totalExitedValidators
        );
        verifier.verify(seal, IMAGE_ID, sha256(journal));
    }
}
