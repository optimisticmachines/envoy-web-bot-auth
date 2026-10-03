//! Cache of verified resolver answers.

use crate::{candidate::VerificationCandidate, config::ResolverCacheSettings};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyBuffer;
use moka::{Expiry, sync::Cache};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use web_bot_auth_protocol::{
    CACHE_VALID_FOR_HEADER, DiscoveryMechanism, ResolveResponse, parse_discovery_target,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct ResolutionCacheKey {
    discovery: DiscoveryMechanism,
    fetch_url: String,
    key_id: String,
}

impl ResolutionCacheKey {
    pub(crate) fn from_candidate(candidate: &VerificationCandidate) -> Option<Self> {
        Self::new(
            candidate.discovery,
            &candidate.signed_url,
            &candidate.key_id,
        )
    }

    fn new(discovery: DiscoveryMechanism, agent_url: &str, key_id: &str) -> Option<Self> {
        let target = parse_discovery_target(agent_url, discovery).ok()?;
        Some(Self {
            discovery,
            fetch_url: target.fetch_url.to_string(),
            key_id: key_id.to_owned(),
        })
    }
}

#[derive(Clone, Debug)]
struct CachedResolution {
    response: Arc<ResolveResponse>,
    valid_until: Instant,
}

struct RemainingLifetime;

impl Expiry<ResolutionCacheKey, CachedResolution> for RemainingLifetime {
    fn expire_after_create(
        &self,
        _key: &ResolutionCacheKey,
        value: &CachedResolution,
        created_at: Instant,
    ) -> Option<Duration> {
        Some(value.valid_until.saturating_duration_since(created_at))
    }
}

#[derive(Clone)]
pub(crate) struct ResolutionCache {
    entries: Cache<ResolutionCacheKey, CachedResolution>,
    max_ttl: Duration,
}

impl ResolutionCache {
    pub(crate) fn new(settings: &ResolverCacheSettings) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(settings.max_entries)
                .expire_after(RemainingLifetime)
                .build(),
            max_ttl: Duration::from_millis(settings.max_ttl_ms),
        }
    }

    pub(crate) fn get(&self, key: &ResolutionCacheKey) -> Option<Arc<ResolveResponse>> {
        self.entries
            .get(key)
            .and_then(|entry| (entry.valid_until > Instant::now()).then_some(entry.response))
    }

    pub(crate) fn insert(
        &self,
        key: ResolutionCacheKey,
        response: ResolveResponse,
        callout_started_at: Instant,
        resolver_valid_for: Duration,
    ) -> bool {
        if !matches!(response, ResolveResponse::Resolved { .. }) {
            return false;
        }
        let valid_for = resolver_valid_for.min(self.max_ttl);
        let Some(valid_until) = callout_started_at.checked_add(valid_for) else {
            return false;
        };
        if valid_until <= Instant::now() {
            return false;
        }
        self.entries.insert(
            key,
            CachedResolution {
                response: Arc::new(response),
                valid_until,
            },
        );
        true
    }
}

pub(crate) fn cache_valid_for(headers: Option<&[(EnvoyBuffer, EnvoyBuffer)]>) -> Option<Duration> {
    let mut values = headers?.iter().filter_map(|(name, value)| {
        name.as_slice()
            .eq_ignore_ascii_case(CACHE_VALID_FOR_HEADER.as_bytes())
            .then_some(value.as_slice())
    });
    let value = values.next()?;
    if values.next().is_some() || value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let milliseconds = std::str::from_utf8(value).ok()?.parse::<u64>().ok()?;
    (milliseconds > 0).then(|| Duration::from_millis(milliseconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use web_bot_auth_protocol::Ed25519Jwk;

    fn key() -> ResolutionCacheKey {
        ResolutionCacheKey {
            discovery: DiscoveryMechanism::JwksUri,
            fetch_url: "https://agent.example/keys".into(),
            key_id: "key".into(),
        }
    }

    fn response() -> ResolveResponse {
        ResolveResponse::Resolved {
            normalized_identifier: "https://agent.example/keys".into(),
            jwk: Ed25519Jwk::new("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".into()),
        }
    }

    #[test]
    fn key_uses_fetch_url_rules() {
        let key = ResolutionCacheKey::new(
            DiscoveryMechanism::JwksUri,
            "HTTPS://AGENT.EXAMPLE:443/keys?generation=2#ignored",
            "key",
        )
        .unwrap();
        assert_eq!(key.fetch_url, "https://agent.example/keys?generation=2");
    }

    #[test]
    fn positive_entries_respect_the_callout_start_and_ttl_cap() {
        let cache = ResolutionCache::new(&ResolverCacheSettings {
            max_entries: 2,
            max_ttl_ms: 40,
        });
        assert!(cache.insert(key(), response(), Instant::now(), Duration::from_secs(60),));
        assert!(cache.get(&key()).is_some());

        let mut delayed_key = key();
        delayed_key.key_id = "delayed".into();
        assert!(!cache.insert(
            delayed_key,
            response(),
            Instant::now() - Duration::from_millis(50),
            Duration::from_secs(60),
        ));
    }

    #[test]
    fn non_positive_and_elapsed_entries_are_not_stored() {
        let cache = ResolutionCache::new(&ResolverCacheSettings::default());
        assert!(!cache.insert(
            key(),
            ResolveResponse::KeyNotFound {
                normalized_identifier: "https://agent.example/keys".into(),
            },
            Instant::now(),
            Duration::from_secs(1),
        ));
        assert!(!cache.insert(
            key(),
            response(),
            Instant::now() - Duration::from_secs(1),
            Duration::from_millis(1),
        ));
    }

    #[test]
    fn freshness_header_is_strict_and_rejects_duplicates() {
        let header = |name: &'static [u8], value: &'static [u8]| {
            (EnvoyBuffer::new(name), EnvoyBuffer::new(value))
        };
        assert_eq!(
            cache_valid_for(Some(&[header(CACHE_VALID_FOR_HEADER.as_bytes(), b"1250",)])),
            Some(Duration::from_millis(1_250))
        );
        assert_eq!(
            cache_valid_for(Some(&[header(CACHE_VALID_FOR_HEADER.as_bytes(), b"0",)])),
            None
        );
        assert_eq!(
            cache_valid_for(Some(&[header(CACHE_VALID_FOR_HEADER.as_bytes(), b" 10",)])),
            None
        );
        assert_eq!(
            cache_valid_for(Some(&[
                header(CACHE_VALID_FOR_HEADER.as_bytes(), b"10"),
                header(CACHE_VALID_FOR_HEADER.as_bytes(), b"10"),
            ])),
            None
        );
        assert_eq!(cache_valid_for(None), None);
    }
}
