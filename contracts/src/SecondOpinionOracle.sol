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
import {Steel} from "risc0/steel/Steel.sol";
import {Journal, ISecondOpinionOracle} from "./ISecondOpinionOracle.sol";
import {IBoundlessMarketCallback} from "boundless/IBoundlessMarketCallback.sol";
import {UUPSUpgradeable} from "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";

struct Report {
    uint256 clBalanceGwei;
    uint256 withdrawalVaultBalanceWei;
    uint256 totalDepositedValidators;
    uint256 totalExitedValidators;
}

/// @title LIP-23 Compatible Oracle implemented using RISC Zero
contract SecondOpinionOracle is ISecondOpinionOracle, IBoundlessMarketCallback, OwnableUpgradeable, UUPSUpgradeable {
    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable VERIFIER;

    /// @notice Image ID of the only zkVM guest to accept verification from.
    bytes32 public immutable IMAGE_ID;

    /// @notice helper reference to the URL hosting the zkVM image
    string public imageUrl;

    /// @notice Seconds per slot
    uint256 public constant SECONDS_PER_SLOT = 12;

    /// @notice Oracle reports stored by refSlot.
    mapping(uint256 => Report) public reports;

    /// @notice Emitted when a new report is stored.
    event ReportUpdated(
        uint256 refSlot,
        uint256 clBalanceGwei,
        uint256 withdrawalVaultBalanceWei,
        uint256 totalDepositedValidators,
        uint256 totalExitedValidators
    );

    /// @notice Initialize the contract, binding it to a specified RISC Zero verifier.
    constructor(IRiscZeroVerifier _verifier, bytes32 _imageId) {
        VERIFIER = _verifier;
        IMAGE_ID = _imageId;

        _disableInitializers();
    }

    function initialize(address initialOwner, string calldata _imageUrl) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        imageUrl = _imageUrl;
    }

    /// @notice Update oracle report. This matches the callback signature expected by Boundless Market.
    ///         but can also be called by other means provided the proof is valid.
    function handleProof(bytes32 imageId, bytes calldata journalBytes, bytes calldata seal) external {
        require(imageId == IMAGE_ID, "Invalid image ID");
        VERIFIER.verify(seal, IMAGE_ID, sha256(journalBytes));

        Journal memory journal = abi.decode(journalBytes, (Journal));
        require(Steel.validateCommitment(journal.commitment), "Invalid Steel commitment");

        reports[journal.refSlot] = Report({
            clBalanceGwei: journal.report.clBalanceGwei,
            withdrawalVaultBalanceWei: journal.report.withdrawalVaultBalanceWei,
            totalDepositedValidators: journal.report.totalDepositedValidators,
            totalExitedValidators: journal.report.totalExitedValidators
        });

        emit ReportUpdated(
            journal.refSlot,
            journal.report.clBalanceGwei,
            journal.report.withdrawalVaultBalanceWei,
            journal.report.totalDepositedValidators,
            journal.report.totalExitedValidators
        );
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

    /// @notice Required by UUPSUpgradeable
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
