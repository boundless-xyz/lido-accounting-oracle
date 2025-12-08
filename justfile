set dotenv-load := true
set dotenv-required := true

build:
    cargo build --release

daemon: build
    ./target/release/cli daemon

## Proving tasks

prove slot: build
    ./target/release/cli prove --slot {{slot}}  --out ./membership_proof_{{slot}}.proof

## Submission to chain

submit slot: build
    ./target/release/cli submit --slot {{slot}} --proof ./aggregate_proof_{{slot}}.proof

# Deploy contracts

deploy:
    cd contracts && forge script script/Deploy.s.sol --rpc-url $ETH_RPC_URL --broadcast --verify

# Running Tests

test:
    RISC0_DEV_MODE=1 cargo test --features skip-verify
