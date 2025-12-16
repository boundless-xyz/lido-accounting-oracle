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

use alloy::hex::FromHex;
use alloy_primitives::B256;
use beacon_state::mainnet::BeaconState;
use ethereum_consensus::{phase0::SignedBeaconBlockHeader, primitives::Root, Fork};
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use reqwest::IntoUrl;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display};
use url::Url;

/// Errors returned by the [BeaconClient].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not parse URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON request middleware failed: {0}")]
    Middleware(#[from] reqwest_middleware::Error),
    #[error("version field does not match data version")]
    VersionMismatch,
}

/// Response returned by the `get_block_header` API.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlockHeaderResponse {
    pub root: Root,
    pub canonical: bool,
    pub header: SignedBeaconBlockHeader,
}

/// Wrapper returned by the API calls.
#[derive(Serialize, Deserialize)]
struct Response<T> {
    data: T,
    #[serde(flatten)]
    meta: HashMap<String, serde_json::Value>,
}

/// Wrapper returned by the API calls that includes a version.
#[derive(Serialize, Deserialize)]
struct VersionedResponse<T> {
    version: Fork,
    #[serde(flatten)]
    inner: Response<T>,
}

/// Simple beacon API client for the `mainnet` preset that can query headers and blocks.
pub struct BeaconClient {
    http: ClientWithMiddleware,
    endpoint: Url,
}

impl BeaconClient {
    /// Creates a new beacon endpoint API client.
    #[allow(dead_code)]
    pub fn new<U: IntoUrl>(endpoint: U) -> Result<Self, Error> {
        let client = reqwest::Client::new();
        Ok(Self {
            http: client.into(),
            endpoint: endpoint.into_url()?,
        })
    }

    /// Creates a new beacon endpoint API client with caching.
    pub fn new_with_cache<U: IntoUrl>(endpoint: U, cache_dir: &str) -> Result<Self, Error> {
        let client = reqwest::Client::new();
        let manager = CACacheManager {
            path: cache_dir.into(),
        };
        let cache = Cache(HttpCache {
            mode: CacheMode::ForceCache,
            manager,
            options: HttpCacheOptions::default(),
        });
        let client_with_middleware = ClientBuilder::new(client).with(cache).build();

        Ok(Self {
            http: client_with_middleware,
            endpoint: endpoint.into_url()?,
        })
    }

    async fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let target = self.endpoint.join(path)?;
        let resp = self.http.get(target).send().await?;
        let value = resp.error_for_status()?.json().await?;
        Ok(value)
    }

    /// Retrieves block details for given block id.
    #[tracing::instrument(skip(self), fields(block_id = %block_id))]
    pub async fn get_block_header(
        &self,
        block_id: impl Display,
    ) -> Result<SignedBeaconBlockHeader, Error> {
        let path = format!("eth/v1/beacon/headers/{block_id}");
        let result: Response<GetBlockHeaderResponse> = self.http_get(&path).await?;
        Ok(result.data.header)
    }

    /// Retrieves block hash for given beacon block id (e.g. slot).
    #[tracing::instrument(skip(self), fields(block_id = %block_id))]
    pub async fn get_eth1_block_hash_at_slot(&self, block_id: impl Display) -> Result<B256, Error> {
        let path = format!("eth/v2/beacon/blocks/{block_id}");
        let result: serde_json::Value = self.http_get(&path).await?;
        let hash_str = result["data"]["message"]["body"]["execution_payload"]["block_hash"]
            .as_str()
            .unwrap();
        Ok(B256::from_hex(&hash_str.trim_start_matches("0x")).unwrap())
    }

    #[tracing::instrument(skip(self), fields(state_id = %state_id))]
    pub async fn get_beacon_state(&self, state_id: impl Display) -> Result<BeaconState, Error> {
        let path = format!("eth/v2/debug/beacon/states/{state_id}");
        let result: VersionedResponse<BeaconState> = self.http_get(&path).await?;
        if result.version.to_string() != result.inner.data.version().to_string() {
            tracing::warn!(
                "FORK: {:?}, Version mismatch: {} != {}",
                result.inner.data.fork(),
                result.version,
                result.inner.data.version()
            );
            return Err(Error::VersionMismatch);
        }
        Ok(result.inner.data)
    }
}
