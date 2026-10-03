//! Resolver request admission, discovery traversal, and key selection.

use super::{
    cache::ResourceKey,
    controls::Limits,
    fetch::{DnsResolver, FetchError, FetchErrorKind, HttpFetcher, ResourceKind},
    loader::ResourceLoader,
    metrics::{Metrics, resolution_result},
    resource::{ParsedResource, ResourceKeyEntry},
    ssrf::DestinationPolicy,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use web_bot_auth_protocol::{
    DiscoveryMechanism, Ed25519Jwk, MAX_AGENT_URL_BYTES, MAX_KEY_ID_BYTES, ResolveRequest,
    ResolveResponse, ResolverApiVersion, parse_discovery_target,
};

const TEST_KEY_THUMBPRINTS: &[&str] = &["poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"];

#[derive(Clone, Debug)]
pub struct Resolution {
    pub response: ResolveResponse,
    pub cache_valid_for: Duration,
}

struct LoadedKeys {
    keys: Vec<ResourceKeyEntry>,
    cache_valid_for: Duration,
}

#[derive(Clone)]
pub struct ResolverService {
    loader: ResourceLoader,
    handlers: Arc<Semaphore>,
    limits: Limits,
    allow_test_keys: bool,
    metrics: Metrics,
}

impl ResolverService {
    pub fn new(
        dns: Arc<dyn DnsResolver>,
        http: Arc<dyn HttpFetcher>,
        destination_policy: DestinationPolicy,
        limits: Limits,
        allow_test_keys: bool,
    ) -> Result<Self, &'static str> {
        limits.validate()?;
        let metrics = Metrics::new();
        Ok(Self {
            loader: ResourceLoader::new(
                dns,
                http,
                destination_policy,
                limits.clone(),
                metrics.clone(),
            ),
            handlers: Arc::new(Semaphore::new(limits.active_handlers)),
            limits,
            allow_test_keys,
            metrics,
        })
    }

    pub fn inbound_body_limit(&self) -> usize {
        self.limits.inbound_body_bytes
    }

    pub async fn resolve(&self, request: ResolveRequest) -> Result<ResolveResponse, FetchError> {
        self.resolve_with_metadata(request)
            .await
            .map(|resolution| resolution.response)
    }

    pub async fn resolve_with_metadata(
        &self,
        request: ResolveRequest,
    ) -> Result<Resolution, FetchError> {
        let started = Instant::now();
        let result = self.resolve_timed(request).await;
        self.metrics
            .resolution(resolution_result(&result), started.elapsed());
        result
    }

    async fn resolve_timed(&self, request: ResolveRequest) -> Result<Resolution, FetchError> {
        let _handler = self.acquire_handler()?;
        tokio::time::timeout(self.limits.resolution_timeout, self.resolve_inner(request))
            .await
            .map_err(|_| FetchError::new(FetchErrorKind::Timeout))?
    }

    fn acquire_handler(&self) -> Result<OwnedSemaphorePermit, FetchError> {
        Arc::clone(&self.handlers)
            .try_acquire_owned()
            .map_err(|_| FetchError::new(FetchErrorKind::Overloaded))
    }

    async fn resolve_inner(&self, request: ResolveRequest) -> Result<Resolution, FetchError> {
        let target = validate_request(&request)?;
        let normalized_identifier = target.normalized_identifier;
        if !self.allow_test_keys && known_test_key(&request.key_id) {
            return Ok(Resolution {
                response: ResolveResponse::KeyNotFound {
                    normalized_identifier,
                },
                cache_valid_for: Duration::ZERO,
            });
        }

        let loaded = self.load_keys(request.discovery, target.fetch_url).await?;
        let response = match select_key(&loaded.keys, &request.key_id) {
            Some(jwk) => ResolveResponse::Resolved {
                normalized_identifier,
                jwk: jwk.clone(),
            },
            None => ResolveResponse::KeyNotFound {
                normalized_identifier,
            },
        };
        Ok(Resolution {
            response,
            cache_valid_for: loaded.cache_valid_for,
        })
    }

    async fn load_keys(
        &self,
        discovery: DiscoveryMechanism,
        fetch_url: url::Url,
    ) -> Result<LoadedKeys, FetchError> {
        match discovery {
            DiscoveryMechanism::Directory | DiscoveryMechanism::JwksUri => {
                let representation = self
                    .loader
                    .load(ResourceKey {
                        url: fetch_url,
                        kind: ResourceKind::Jwks,
                    })
                    .await?;
                match &representation.resource {
                    ParsedResource::Jwks(keys) => Ok(LoadedKeys {
                        keys: keys.clone(),
                        cache_valid_for: representation.remaining_freshness(Instant::now()),
                    }),
                    ParsedResource::Cimd(_) => {
                        Err(FetchError::new(FetchErrorKind::InvalidResource))
                    }
                }
            }
            DiscoveryMechanism::Cimd => {
                let metadata = self
                    .loader
                    .load(ResourceKey {
                        url: fetch_url,
                        kind: ResourceKind::Cimd,
                    })
                    .await?;
                let cimd = match &metadata.resource {
                    ParsedResource::Cimd(cimd) => cimd.clone(),
                    ParsedResource::Jwks(_) => {
                        return Err(FetchError::new(FetchErrorKind::InvalidResource));
                    }
                };
                if let Some(keys) = cimd.inline_jwks {
                    return Ok(LoadedKeys {
                        keys,
                        cache_valid_for: metadata.remaining_freshness(Instant::now()),
                    });
                }
                let jwks_url = cimd
                    .jwks_uri
                    .ok_or_else(|| FetchError::new(FetchErrorKind::InvalidResource))?;
                let jwks = self
                    .loader
                    .load(ResourceKey {
                        url: jwks_url,
                        kind: ResourceKind::Jwks,
                    })
                    .await?;
                match &jwks.resource {
                    ParsedResource::Jwks(keys) => Ok(LoadedKeys {
                        keys: keys.clone(),
                        cache_valid_for: metadata
                            .remaining_freshness(Instant::now())
                            .min(jwks.remaining_freshness(Instant::now())),
                    }),
                    ParsedResource::Cimd(_) => {
                        Err(FetchError::new(FetchErrorKind::InvalidResource))
                    }
                }
            }
        }
    }
}

fn validate_request(
    request: &ResolveRequest,
) -> Result<web_bot_auth_protocol::DiscoveryTarget, FetchError> {
    if request.api_version != ResolverApiVersion::V1
        || request.key_id.is_empty()
        || request.key_id.len() > MAX_KEY_ID_BYTES
        || request.agent_url.len() > MAX_AGENT_URL_BYTES
    {
        return Err(FetchError::new(FetchErrorKind::BadRequest));
    }
    parse_discovery_target(&request.agent_url, request.discovery)
        .map_err(|_| FetchError::new(FetchErrorKind::BadRequest))
}

fn select_key<'a>(keys: &'a [ResourceKeyEntry], key_id: &str) -> Option<&'a Ed25519Jwk> {
    keys.iter()
        .find(|key| key.kid.as_deref() == Some(key_id))
        .or_else(|| keys.iter().find(|key| key.jwk.b64_thumbprint() == key_id))
        .map(|key| &key.jwk)
}

fn known_test_key(key_id: &str) -> bool {
    TEST_KEY_THUMBPRINTS.contains(&key_id)
}
