use beacon_state::mainnet::ElectraBeaconState;
use ethereum_consensus::capella::presets::mainnet::{
    HistoricalBatch, HistoricalSummary, Validator,
};
use ethereum_consensus::deneb::mainnet::SLOTS_PER_HISTORICAL_ROOT;
use ethereum_consensus::ssz::prelude::*;
use lido_oracle_core::mainnet::WITHDRAWAL_CREDENTIALS;

pub const CAPELLA_FORK_SLOT: u64 = 6209536;

pub struct TestStateBuilder {
    inner: ElectraBeaconState,
}

impl TestStateBuilder {
    pub fn new(slot: u64) -> Self {
        Self {
            inner: ElectraBeaconState {
                slot,
                ..Default::default()
            },
        }
    }

    pub fn with_validators(&mut self, n_empty_validators: usize) {
        for _ in 0..n_empty_validators {
            self.inner.validators.push(Validator {
                effective_balance: 99,
                ..Default::default()
            });
            self.inner.balances.push(99);
        }
    }

    pub fn with_lido_validators(&mut self, n_lido_validators: usize) {
        for _ in 0..n_lido_validators {
            self.inner.validators.push(Validator {
                withdrawal_credentials: WITHDRAWAL_CREDENTIALS.as_slice().try_into().unwrap(),
                exit_epoch: 123,
                effective_balance: 10,
                ..Default::default()
            });
            self.inner.balances.push(10);
        }
    }

    pub fn with_prior_state(
        &mut self,
        prior_state: &beacon_state::mainnet::BeaconState,
    ) -> Option<HistoricalBatch> {
        let slot = self.inner.slot;
        let prior_slot = prior_state.slot();
        assert!(slot > prior_slot, "prior_state.slot must be less than slot");
        let index: usize = (prior_slot % (SLOTS_PER_HISTORICAL_ROOT as u64))
            .try_into()
            .unwrap();

        // if a short range add the state root to the state_roots list
        if slot <= prior_slot + (SLOTS_PER_HISTORICAL_ROOT as u64) {
            self.inner.state_roots[index] = prior_state.hash_tree_root().unwrap();
            None
        } else {
            // if a long range build a HistoricalSummary containing the state root and add this so the historical_summaries list
            let mut batch = HistoricalBatch::default();
            batch.state_roots[index] = prior_state.hash_tree_root().unwrap();
            let summary = HistoricalSummary {
                block_summary_root: batch.block_roots.hash_tree_root().unwrap(),
                state_summary_root: batch.state_roots.hash_tree_root().unwrap(),
            };
            self.inner
                .historical_summaries
                .extend(std::iter::repeat(summary).take(
                    ((prior_slot - CAPELLA_FORK_SLOT) / (SLOTS_PER_HISTORICAL_ROOT as u64))
                        as usize
                        + 1,
                ));
            Some(batch)
        }
    }

    pub fn build(self) -> beacon_state::mainnet::BeaconState {
        beacon_state::mainnet::BeaconState::Electra(self.inner)
    }
}
