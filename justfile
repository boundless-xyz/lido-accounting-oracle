set dotenv-load := true
set dotenv-required := true

build:
    cargo build --release

## Proving tasks

prove_init slot: build
    ./target/release/cli --slot {{slot}} gen-input --out ./membership_proof_{{slot}}.proof initial

prove_continuation prior_slot slot: build
    ./target/release/cli --slot {{slot}} prove --out ./membership_proof_{{slot}}.proof continuation-from ./membership_proof_{{prior_slot}}.proof

## Submission to chain

submit slot: build
    ./target/release/cli --slot {{slot}} submit --proof ./aggregate_proof_{{slot}}.proof

# Deploy contracts

deploy:
    cd contracts && forge script script/Deploy.s.sol --rpc-url $ETH_RPC_URL --broadcast --verify

# Running Tests

test:
    RISC0_DEV_MODE=1 cargo test --features skip-verify
