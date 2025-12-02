use alloy_primitives::{address, Address};
use alloy_sol_types::sol;
use alloy_sol_types::{SolCall, SolType};

pub const ADDRESS: Address = address!("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

sol! {
    #[sol(rpc)]
    contract Eip4788 {
      function getBlockRoot(uint256 timestamp) external view returns (bytes32);
    }
}

use Eip4788::getBlockRootCall;

/// A wrapper around the auto-generated call type to override ABI encoding
pub(crate) struct Eip4788Call {
    inner: Eip4788::getBlockRootCall,
}

/// Forward all implementations to the inner call except for ABI encode
/// which omits the selector.
impl SolCall for Eip4788Call {
    const SIGNATURE: &'static str = "getBlockRoot(uint256)";
    const SELECTOR: [u8; 4] = [0, 0, 0, 0];

    type Parameters<'a> = <getBlockRootCall as alloy_sol_types::SolCall>::Parameters<'a>;
    type Token<'a> = <getBlockRootCall as alloy_sol_types::SolCall>::Token<'a>;

    type Return = <getBlockRootCall as alloy_sol_types::SolCall>::Return;
    type ReturnTuple<'a> = <getBlockRootCall as alloy_sol_types::SolCall>::ReturnTuple<'a>;
    type ReturnToken<'a> = <getBlockRootCall as alloy_sol_types::SolCall>::ReturnToken<'a>;

    #[inline]
    fn new<'a>(tuple: <Self::Parameters<'a> as SolType>::RustType) -> Self {
        Eip4788Call {
            inner: <getBlockRootCall as alloy_sol_types::SolCall>::new(tuple),
        }
    }

    /// Override default impl to skip prepending the selector
    #[inline]
    fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.abi_encoded_size());
        self.abi_encode_raw(&mut out);
        out
    }

    #[inline]
    fn tokenize(&self) -> Self::Token<'_> {
        <getBlockRootCall as alloy_sol_types::SolCall>::tokenize(&self.inner)
    }

    #[inline]
    fn tokenize_returns(ret: &Self::Return) -> Self::ReturnToken<'_> {
        <getBlockRootCall as alloy_sol_types::SolCall>::tokenize_returns(ret)
    }

    #[inline]
    fn abi_decode_returns(data: &[u8]) -> alloy_sol_types::Result<Self::Return> {
        <getBlockRootCall as alloy_sol_types::SolCall>::abi_decode_returns(data)
    }

    #[inline]
    fn abi_decode_returns_validate(data: &[u8]) -> alloy_sol_types::Result<Self::Return> {
        <getBlockRootCall as alloy_sol_types::SolCall>::abi_decode_returns_validate(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::ANVIL_CHAIN_SPEC;

    use super::*;
    use alloy::{
        node_bindings::Anvil,
        providers::{ext::AnvilApi, Provider, ProviderBuilder},
        rpc::types::eth::transaction::{TransactionInput, TransactionRequest},
    };
    use alloy_primitives::{Bytes, TxKind, B256, U256};
    use hex_literal::hex;
    use risc0_steel::{ethereum::EthEvmEnv, Contract};

    // The bytecode for the EIP-4788 contract
    // retrieved with `cast code 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02`
    const CODE: [u8; 97] = hex!("3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500");
    const HISTORY_BUFFER_LENGTH: u64 = 8_191;

    #[tokio::test]
    async fn test_eip4788_call() {
        let anvil = Anvil::new().args(["--hardfork", "cancun"]).spawn();
        let rpc_url = anvil.endpoint();

        let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());

        provider
            .anvil_set_code(ADDRESS, Bytes::copy_from_slice(&CODE))
            .await
            .unwrap();

        let header_timestamp = 1_234_567_u64;
        let block_root = B256::from([0x33_u8; 32]);

        let index = header_timestamp % HISTORY_BUFFER_LENGTH;
        let timestamp_slot = U256::from(index);
        let root_slot = U256::from(index + HISTORY_BUFFER_LENGTH);

        provider
            .anvil_set_storage_at(
                ADDRESS,
                timestamp_slot,
                B256::from(U256::from(header_timestamp)),
            )
            .await
            .unwrap();

        provider
            .anvil_set_storage_at(ADDRESS, root_slot, block_root)
            .await
            .unwrap();

        // progress the block so the state is committed in the header
        provider.anvil_mine(Some(1), Some(1)).await.unwrap();

        let call = Eip4788Call::new((U256::from(header_timestamp),));
        let calldata = call.abi_encode();

        let mut tx = TransactionRequest::default();
        tx.to = Some(TxKind::Call(ADDRESS));
        tx.input = TransactionInput::new(Bytes::from(calldata.clone()));

        let response = provider.call(tx).await.unwrap();

        let decoded = Eip4788Call::abi_decode_returns(response.as_ref()).unwrap();
        assert_eq!(decoded, block_root);

        // Also test it works with Steel

        let mut env = EthEvmEnv::builder()
            .provider(provider)
            .chain_spec(&ANVIL_CHAIN_SPEC)
            .build()
            .await
            .unwrap();

        let mut contract = Contract::preflight(ADDRESS, &mut env);
        assert_eq!(
            contract.call_builder(&call).call().await.unwrap(),
            block_root
        );

        let input = env.into_input().await.unwrap();
        let evm_env = input.into_env(&ANVIL_CHAIN_SPEC);
        assert_eq!(
            Contract::new(ADDRESS, &evm_env).call_builder(&call).call(),
            block_root
        );
    }
}
