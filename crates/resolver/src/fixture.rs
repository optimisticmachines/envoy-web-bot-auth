//! Deterministic discovery transport for kind integration tests.
//!
//! This module is compiled only with the non default `kind-fixtures` feature.
//! It is not reachable from the production `serve` command.

use super::{
    DnsResolver, FetchError, FetchErrorKind, FetchRequest, FetchResponse, HttpFetcher, ResourceKind,
};
use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use web_bot_auth_protocol::Ed25519Jwk;

pub const FIXTURE_AGENT_URL: &str = "https://fixture.web-bot-auth.test";
pub const FIXTURE_AGENT_B_URL: &str = "https://fixture-b.web-bot-auth.test";
const FIXTURE_HOST: &str = "fixture.web-bot-auth.test";
const FIXTURE_B_HOST: &str = "fixture-b.web-bot-auth.test";
const AGENT_A_X: &str = "HeASB7bZRkoeg6vmjyELll2w181pbxHrCaCjIoBWtdo";
const AGENT_B_X: &str = "BPGSJ5ZwWg-DHPYthdEJqbGMINULnW91nGkytUXlW4s";

/// The only mutable behavior exposed by the fixture-only resolver command.
/// All modes return bounded, deterministic responses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureMode {
    HealthyV1,
    CacheableV1,
    RotatedV2,
    Malformed,
    Unavailable,
    Delayed,
}

impl FixtureMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HealthyV1 => "healthy_v1",
            Self::CacheableV1 => "cacheable_v1",
            Self::RotatedV2 => "rotated_v2",
            Self::Malformed => "malformed",
            Self::Unavailable => "unavailable",
            Self::Delayed => "delayed",
        }
    }
}

#[derive(Clone)]
pub struct FixtureTransport {
    mode: Arc<RwLock<FixtureMode>>,
}

impl Default for FixtureTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureTransport {
    pub fn new() -> Self {
        Self {
            mode: Arc::new(RwLock::new(FixtureMode::HealthyV1)),
        }
    }

    pub async fn set_mode(&self, mode: FixtureMode) {
        *self.mode.write().await = mode;
    }

    pub async fn mode(&self) -> FixtureMode {
        *self.mode.read().await
    }

    fn response(request: &FetchRequest, mode: FixtureMode) -> Result<FetchResponse, FetchError> {
        if mode == FixtureMode::Unavailable {
            return Err(FetchError::new(FetchErrorKind::Transport));
        }
        let body = match mode {
            FixtureMode::Malformed => b"{not-json".to_vec(),
            FixtureMode::HealthyV1
            | FixtureMode::CacheableV1
            | FixtureMode::RotatedV2
            | FixtureMode::Delayed => {
                let x = if request.url.host_str() == Some(FIXTURE_B_HOST) {
                    AGENT_B_X
                } else {
                    match mode {
                        FixtureMode::RotatedV2 => AGENT_B_X,
                        _ => AGENT_A_X,
                    }
                };
                let agent_url = match request.url.host_str() {
                    Some(FIXTURE_B_HOST) => FIXTURE_AGENT_B_URL,
                    _ => FIXTURE_AGENT_URL,
                };
                match request.kind {
                    ResourceKind::Jwks => {
                        let kid = if request.url.path()
                            == "/.well-known/http-message-signatures-directory"
                        {
                            format!(
                                r#", "kid":"{}""#,
                                Ed25519Jwk::new(x.to_owned()).b64_thumbprint()
                            )
                        } else {
                            String::new()
                        };
                        format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519"{kid},"x":"{x}"}}]}}"#)
                            .into_bytes()
                    }
                    ResourceKind::Cimd => format!(
                        r#"{{"client_id":"{}","jwks_uri":"{agent_url}/jwks"}}"#,
                        request.url
                    )
                    .into_bytes(),
                }
            }
            FixtureMode::Unavailable => unreachable!("handled before response construction"),
        };
        let content_type = match request.kind {
            ResourceKind::Jwks
                if request.url.path() == "/.well-known/http-message-signatures-directory" =>
            {
                "application/http-message-signatures-directory+json"
            }
            ResourceKind::Jwks => "application/jwk-set+json",
            ResourceKind::Cimd => "application/json",
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        // The default modes revalidate so rotation remains observable without
        // waiting for a cache lifetime to elapse. The explicit cacheable mode
        // exists only for bounded module-cache load measurements.
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(if mode == FixtureMode::CacheableV1 {
                "max-age=300"
            } else {
                "no-cache"
            }),
        );
        Ok(FetchResponse {
            status: StatusCode::OK,
            headers,
            body,
        })
    }
}

#[async_trait]
impl DnsResolver for FixtureTransport {
    async fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, FetchError> {
        if host != FIXTURE_HOST && host != FIXTURE_B_HOST {
            return Err(FetchError::new(FetchErrorKind::Dns));
        }
        // This address is never contacted: HttpFetcher below is injected into
        // the resolver. It is globally routable so the ordinary address policy
        // remains part of the exercised resolution path.
        Ok(vec!["8.8.8.8".parse().expect("literal IP is valid")])
    }
}

#[async_trait]
impl HttpFetcher for FixtureTransport {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        if !matches!(request.url.host_str(), Some(FIXTURE_HOST | FIXTURE_B_HOST)) {
            return Err(FetchError::new(FetchErrorKind::Transport));
        }
        let mode = self.mode().await;
        if mode == FixtureMode::Delayed {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Self::response(&request, mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DestinationPolicy, Limits, ResolverService};
    use std::sync::Arc;
    use web_bot_auth_protocol::{
        DiscoveryMechanism, ResolveRequest, ResolveResponse, ResolverApiVersion,
    };

    fn request() -> FetchRequest {
        FetchRequest {
            url: url::Url::parse("https://fixture.web-bot-auth.test/jwks").unwrap(),
            kind: ResourceKind::Jwks,
            headers: HeaderMap::new(),
            selected_ip: "8.8.8.8".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn fixture_transport_rotates_and_can_fail() {
        let fixture = FixtureTransport::new();
        let response = FixtureTransport::response(&request(), fixture.mode().await).unwrap();
        assert!(
            std::str::from_utf8(&response.body)
                .unwrap()
                .contains(AGENT_A_X)
        );

        fixture.set_mode(FixtureMode::RotatedV2).await;
        let response = FixtureTransport::response(&request(), fixture.mode().await).unwrap();
        assert!(
            std::str::from_utf8(&response.body)
                .unwrap()
                .contains(AGENT_B_X)
        );

        fixture.set_mode(FixtureMode::Unavailable).await;
        assert!(FixtureTransport::response(&request(), fixture.mode().await).is_err());
    }

    #[test]
    fn cacheable_fixture_mode_is_explicit() {
        let default_response = FixtureTransport::response(&request(), FixtureMode::HealthyV1)
            .expect("default fixture response is available");
        assert_eq!(
            default_response.headers.get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-cache"))
        );

        let cacheable_response = FixtureTransport::response(&request(), FixtureMode::CacheableV1)
            .expect("cacheable fixture response is available");
        assert_eq!(
            cacheable_response.headers.get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("max-age=300"))
        );
    }

    #[tokio::test]
    async fn agent_a_directory_response_resolves_its_thumbprint() {
        let fixture = FixtureTransport::new();
        let directory_url = url::Url::parse(
            "https://fixture.web-bot-auth.test/.well-known/http-message-signatures-directory",
        )
        .expect("fixture directory URL is valid");
        let fetched = FixtureTransport::response(
            &FetchRequest {
                url: directory_url.clone(),
                kind: ResourceKind::Jwks,
                headers: http::HeaderMap::new(),
                selected_ip: "8.8.8.8".parse().expect("fixture address is valid"),
            },
            FixtureMode::HealthyV1,
        )
        .expect("fixture response is available");
        let expected_key_id = Ed25519Jwk::new(AGENT_A_X.to_owned()).b64_thumbprint();
        assert!(
            std::str::from_utf8(&fetched.body)
                .expect("fixture body is UTF-8")
                .contains(&expected_key_id),
            "fixture directory body has the expected key thumbprint"
        );
        crate::resource::parse_resource(
            ResourceKind::Jwks,
            &directory_url,
            &fetched.body,
            Limits::default().max_keys,
        )
        .expect("fixture directory body parses");
        let service = ResolverService::new(
            Arc::new(fixture.clone()),
            Arc::new(fixture),
            DestinationPolicy::default(),
            Limits::default(),
            true,
        )
        .expect("fixture limits are valid");
        let response = service
            .resolve(ResolveRequest {
                api_version: ResolverApiVersion::V1,
                discovery: DiscoveryMechanism::Directory,
                agent_url: FIXTURE_AGENT_URL.to_owned(),
                key_id: expected_key_id,
            })
            .await
            .expect("fixture directory response is valid");
        assert!(matches!(response, ResolveResponse::Resolved { .. }));
    }
}
