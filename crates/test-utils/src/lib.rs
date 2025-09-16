use beacon_state::mainnet::ElectraBeaconState;
use ethereum_consensus::capella::presets::mainnet::Validator;
use lido_oracle_core::mainnet::WITHDRAWAL_CREDENTIALS;

pub const CAPELLA_FORK_SLOT: u64 = 6209536;

#[derive(Clone)]
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

    pub fn build(self) -> beacon_state::mainnet::BeaconState {
        beacon_state::mainnet::BeaconState::Electra(self.inner)
    }
}
