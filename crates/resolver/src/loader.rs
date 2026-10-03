use super::{
    cache::{
        CacheStore, RefreshOutcome, Representation, ResourceKey, cache_request,
        representation_from_response,
    },
    controls::{COALESCED_FAILURE_TTL, Limits, MAX_FAILURE_BACKOFF, WorkControls},
    fetch::{FailureClass, FetchError, FetchErrorKind, FetchRequest, SharedDns, SharedFetcher},
    metrics::{Metrics, fetch_result},
    ssrf::{DestinationPolicy, validate_all_addresses},
};
use http_cache_semantics::BeforeRequest;
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

#[derive(Clone)]
pub(super) struct ResourceLoader {
    dns: SharedDns,
    http: SharedFetcher,
    destination_policy: DestinationPolicy,
    cache: CacheStore,
    controls: Arc<WorkControls>,
    max_keys: usize,
    metrics: Metrics,
}

impl ResourceLoader {
    pub(super) fn new(
        dns: SharedDns,
        http: SharedFetcher,
        destination_policy: DestinationPolicy,
        limits: Limits,
        metrics: Metrics,
    ) -> Self {
        Self {
            dns,
            http,
            destination_policy,
            cache: CacheStore::new(limits.state_entries, MAX_FAILURE_BACKOFF, metrics.clone()),
            controls: Arc::new(WorkControls::new(limits.clone())),
            max_keys: limits.max_keys,
            metrics,
        }
    }

    pub(super) async fn load(&self, key: ResourceKey) -> Result<Arc<Representation>, FetchError> {
        self.cache.load(self, key).await
    }

    pub(super) async fn refresh(
        &self,
        key: ResourceKey,
        previous: Option<Arc<Representation>>,
    ) -> RefreshOutcome {
        self.metrics.cache_event("refresh");
        let result = self.refresh_inner(&key, previous).await;
        let valid_for = match &result {
            Ok(representation) => {
                if let Some(transition) = self.controls.success(&key).await {
                    eprintln!(
                        "resolver event=circuit_transition reason={}",
                        transition.reason()
                    );
                }
                if representation.policy.is_storable() {
                    Duration::from_millis(50)
                } else {
                    Duration::ZERO
                }
            }
            Err(error) => match error.class() {
                FailureClass::Transient => {
                    let (backoff, transition) =
                        self.controls.failure_backoff(&key, error.retry_after).await;
                    if let Some(transition) = transition {
                        eprintln!(
                            "resolver event=circuit_transition reason={}",
                            transition.reason()
                        );
                    }
                    backoff
                }
                FailureClass::CircuitOpen => self.controls.circuit_remaining(&key).await,
                FailureClass::Permanent | FailureClass::LoadShed => COALESCED_FAILURE_TTL,
            },
        };
        RefreshOutcome {
            result,
            valid_until: Instant::now() + valid_for,
        }
    }

    async fn refresh_inner(
        &self,
        key: &ResourceKey,
        previous: Option<Arc<Representation>>,
    ) -> Result<Arc<Representation>, FetchError> {
        self.controls.check_circuit(key).await?;
        self.destination_policy
            .validate_url(&key.url)
            .map_err(|_| FetchError::new(FetchErrorKind::UnsafeAddress))?;
        let host = key
            .url
            .host_str()
            .ok_or_else(|| FetchError::new(FetchErrorKind::InvalidResource))?;
        let port = key
            .url
            .port_or_known_default()
            .ok_or_else(|| FetchError::new(FetchErrorKind::InvalidResource))?;
        let origin = key.url.origin().ascii_serialization();
        let _permit = self.controls.begin_fetch(origin).await?;
        let addresses = self.dns.resolve(host, port).await?;
        let addresses = validate_all_addresses(&addresses)
            .map_err(|_| FetchError::new(FetchErrorKind::UnsafeAddress))?;
        let selected_ip = addresses[0];
        self.controls.check_ip(selected_ip).await?;

        let request = cache_request(key)?;
        let headers = match previous.as_ref() {
            Some(old) => match old.policy.before_request(&request, SystemTime::now()) {
                BeforeRequest::Stale { request, .. } => request.headers,
                BeforeRequest::Fresh(parts) => parts.headers,
            },
            None => request.headers().clone(),
        };
        // The refresh leader holds the permit for the whole network request.
        let fetch_started = Instant::now();
        let response = self
            .http
            .fetch(FetchRequest {
                url: key.url.clone(),
                kind: key.kind,
                headers,
                selected_ip,
            })
            .await;
        let response = match response {
            Ok(response) => {
                self.metrics
                    .fetch(fetch_result(Ok(())), fetch_started.elapsed());
                response
            }
            Err(error) => {
                self.metrics
                    .fetch(fetch_result(Err(error.kind)), fetch_started.elapsed());
                return Err(error);
            }
        };
        let representation =
            representation_from_response(key, request, previous, response, self.max_keys)?;
        self.cache.publish(key, Arc::clone(&representation)).await;
        Ok(representation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cache::{apply_default_freshness, parse_stale_if_error},
        controls::{CircuitTransition, WorkControls},
        fetch::FetchResponse,
        fetch::ResourceKind,
        service::ResolverService,
    };
    use async_trait::async_trait;
    use http::HeaderMap;
    use std::{
        collections::VecDeque,
        net::IpAddr,
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use url::Url;
    use web_bot_auth_protocol::{
        DiscoveryMechanism, Ed25519Jwk, ResolveRequest, ResolveResponse, ResolverApiVersion,
    };

    const X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

    #[derive(Clone)]
    struct FakeDns;

    #[async_trait]
    impl super::super::fetch::DnsResolver for FakeDns {
        async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, FetchError> {
            Ok(vec!["8.8.8.8".parse().unwrap()])
        }
    }

    struct FakeHttp {
        calls: AtomicUsize,
        body: Vec<u8>,
    }

    #[async_trait]
    impl super::super::fetch::HttpFetcher for FakeHttp {
        async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static(match request.kind {
                    ResourceKind::Jwks => "application/jwk-set+json",
                    ResourceKind::Cimd => "application/json",
                }),
            );
            headers.insert(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("max-age=3600"),
            );
            Ok(FetchResponse {
                status: http::StatusCode::OK,
                headers,
                body: self.body.clone(),
            })
        }
    }

    fn request(key_id: String) -> ResolveRequest {
        ResolveRequest {
            api_version: ResolverApiVersion::V1,
            discovery: DiscoveryMechanism::JwksUri,
            agent_url: "https://agent.example/keys?generation=2#ignored".into(),
            key_id,
        }
    }

    fn high_rate_limits() -> Limits {
        Limits {
            global_fetch_rate: 1_000,
            global_fetch_burst: 1_000,
            origin_fetch_rate: 1_000,
            origin_fetch_burst: 1_000,
            ip_fetch_rate: 1_000,
            ip_fetch_burst: 1_000,
            ..Limits::default()
        }
    }

    struct ScriptedHttp {
        calls: AtomicUsize,
        responses: StdMutex<VecDeque<Result<FetchResponse, FetchError>>>,
        request_headers: StdMutex<Vec<HeaderMap>>,
    }

    #[async_trait]
    impl super::super::fetch::HttpFetcher for ScriptedHttp {
        async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.request_headers.lock().unwrap().push(request.headers);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted response")
        }
    }

    fn response(body: Vec<u8>, cache_control: &'static str) -> FetchResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/jwk-set+json"),
        );
        headers.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static(cache_control),
        );
        FetchResponse {
            status: http::StatusCode::OK,
            headers,
            body,
        }
    }

    fn jwks(x: Option<&str>) -> Vec<u8> {
        match x {
            Some(x) => {
                format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}]}}"#).into_bytes()
            }
            None => br#"{"keys":[]}"#.to_vec(),
        }
    }

    #[test]
    fn must_revalidate_disables_stale_if_error() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("max-age=0, stale-if-error=60, must-revalidate"),
        );
        assert_eq!(parse_stale_if_error(&headers), None);
    }

    #[test]
    fn local_freshness_preserves_existing_cache_directives() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("public"),
        );
        apply_default_freshness(&mut headers);
        assert_eq!(
            headers
                .get_all(http::header::CACHE_CONTROL)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect::<Vec<_>>(),
            vec!["public", "max-age=300"]
        );

        let mut no_store = HeaderMap::new();
        no_store.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        apply_default_freshness(&mut no_store);
        assert_eq!(
            no_store.get_all(http::header::CACHE_CONTROL).iter().count(),
            1
        );
    }

    #[tokio::test]
    async fn one_resource_fetch_serves_one_thousand_key_ids() {
        let http = Arc::new(FakeHttp {
            calls: AtomicUsize::new(0),
            body: format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{X}"}}]}}"#).into_bytes(),
        });
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http.clone(),
            DestinationPolicy::default(),
            Limits::default(),
            true,
        )
        .unwrap();

        for index in 0..1_000 {
            let _ = service
                .resolve(request(format!("key-{index}")))
                .await
                .unwrap();
        }
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn coalesced_followers_do_not_consume_outbound_capacity() {
        struct SlowHttp(AtomicUsize);
        #[async_trait]
        impl super::super::fetch::HttpFetcher for SlowHttp {
            async fn fetch(&self, _request: FetchRequest) -> Result<FetchResponse, FetchError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(25)).await;
                Ok(response(jwks(Some(X)), "max-age=3600"))
            }
        }

        let http = Arc::new(SlowHttp(AtomicUsize::new(0)));
        let mut limits = high_rate_limits();
        limits.outbound_fetches = 1;
        limits.active_handlers = 128;
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http.clone(),
            DestinationPolicy::default(),
            limits,
            true,
        )
        .unwrap();
        let mut tasks = Vec::new();
        for index in 0..100 {
            let service = service.clone();
            tasks.push(tokio::spawn(async move {
                service.resolve(request(format!("missing-{index}"))).await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(http.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn outbound_capacity_is_held_before_dns() {
        let mut limits = high_rate_limits();
        limits.outbound_fetches = 1;
        let controls = WorkControls::new(limits);
        let permit = controls.begin_fetch("https://one.example:443".into()).await;
        assert!(permit.is_ok());
        assert_eq!(
            controls
                .begin_fetch("https://two.example:443".into())
                .await
                .unwrap_err()
                .kind,
            FetchErrorKind::Overloaded
        );
        drop(permit);
    }

    #[tokio::test]
    async fn each_outbound_rate_scope_sheds_without_waiting() {
        let mut limits = high_rate_limits();
        limits.global_fetch_rate = 1;
        limits.global_fetch_burst = 1;
        limits.origin_fetch_rate = 1;
        limits.origin_fetch_burst = 1;
        limits.ip_fetch_rate = 1;
        limits.ip_fetch_burst = 1;
        let controls = WorkControls::new(limits);

        let first = controls
            .begin_fetch("https://one.example:443".into())
            .await
            .unwrap();
        assert_eq!(
            controls
                .begin_fetch("https://one.example:443".into())
                .await
                .unwrap_err()
                .kind,
            FetchErrorKind::RateLimited
        );
        drop(first);

        let second = controls
            .begin_fetch("https://two.example:443".into())
            .await
            .unwrap_err();
        assert_eq!(second.kind, FetchErrorKind::RateLimited);
        assert!(controls.check_ip("8.8.8.8".parse().unwrap()).await.is_ok());
        assert_eq!(
            controls
                .check_ip("8.8.8.8".parse().unwrap())
                .await
                .unwrap_err()
                .kind,
            FetchErrorKind::RateLimited
        );
    }

    #[tokio::test]
    async fn new_origins_are_bounded_and_circuit_resets() {
        let mut limits = high_rate_limits();
        limits.new_origins_per_minute = 1;
        let controls = WorkControls::new(limits);
        let first = controls
            .begin_fetch("https://one.example:443".into())
            .await
            .unwrap();
        drop(first);
        assert_eq!(
            controls
                .begin_fetch("https://two.example:443".into())
                .await
                .unwrap_err()
                .kind,
            FetchErrorKind::RateLimited
        );

        let key = ResourceKey {
            url: Url::parse("https://one.example/keys").unwrap(),
            kind: ResourceKind::Jwks,
        };
        assert_eq!(
            controls.failure_backoff(&key, None).await,
            (Duration::from_secs(5), None)
        );
        assert_eq!(
            controls.failure_backoff(&key, None).await,
            (Duration::from_secs(10), None)
        );
        let (_, transition) = controls.failure_backoff(&key, None).await;
        assert_eq!(transition, Some(CircuitTransition::Opened));
        assert_eq!(
            controls.check_circuit(&key).await.unwrap_err().kind,
            FetchErrorKind::CircuitOpen
        );
        assert_eq!(
            controls.success(&key).await,
            Some(CircuitTransition::Closed)
        );
        assert!(controls.check_circuit(&key).await.is_ok());
    }

    #[tokio::test]
    async fn new_origin_tracker_respects_state_capacity() {
        let mut limits = high_rate_limits();
        limits.new_origins_per_minute = 10;
        limits.state_entries = 1;
        let controls = WorkControls::new(limits);
        let first = controls
            .begin_fetch("https://one.example:443".into())
            .await
            .unwrap();
        drop(first);
        assert_eq!(
            controls
                .begin_fetch("https://two.example:443".into())
                .await
                .unwrap_err()
                .kind,
            FetchErrorKind::RateLimited
        );
    }

    #[tokio::test]
    async fn cimd_traversal_stops_after_metadata_and_one_jwks() {
        struct CimdHttp(AtomicUsize);
        #[async_trait]
        impl super::super::fetch::HttpFetcher for CimdHttp {
            async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
                let call = self.0.fetch_add(1, Ordering::SeqCst);
                let mut headers = HeaderMap::new();
                headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
                headers.insert(
                    http::header::CACHE_CONTROL,
                    http::HeaderValue::from_static(if call == 0 {
                        "max-age=60"
                    } else {
                        "max-age=1"
                    }),
                );
                let body = if call == 0 && request.kind == ResourceKind::Cimd {
                    br#"{"client_id":"https://agent.example/metadata","jwks_uri":"https://keys.example/jwks"}"#.to_vec()
                } else {
                    format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{X}"}}]}}"#)
                        .into_bytes()
                };
                Ok(FetchResponse {
                    status: http::StatusCode::OK,
                    headers,
                    body,
                })
            }
        }
        let http = Arc::new(CimdHttp(AtomicUsize::new(0)));
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http.clone(),
            DestinationPolicy::default(),
            Limits::default(),
            true,
        )
        .unwrap();
        let mut request = request("missing".into());
        request.discovery = DiscoveryMechanism::Cimd;
        request.agent_url = "https://agent.example/metadata".into();
        let resolution = service.resolve_with_metadata(request).await.unwrap();
        assert!(resolution.cache_valid_for > Duration::ZERO);
        assert!(resolution.cache_valid_for <= Duration::from_secs(1));
        assert_eq!(http.0.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn no_store_is_not_published() {
        let http = Arc::new(ScriptedHttp {
            calls: AtomicUsize::new(0),
            responses: StdMutex::new(VecDeque::from([
                Ok(response(jwks(Some(X)), "no-store")),
                Ok(response(jwks(Some(X)), "no-store")),
            ])),
            request_headers: StdMutex::new(Vec::new()),
        });
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http.clone(),
            DestinationPolicy::default(),
            high_rate_limits(),
            true,
        )
        .unwrap();
        let first = service
            .resolve_with_metadata(request("missing".into()))
            .await
            .unwrap();
        assert_eq!(first.cache_valid_for, Duration::ZERO);
        service.resolve(request("missing".into())).await.unwrap();
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn no_store_invalidates_an_existing_representation() {
        let http = Arc::new(ScriptedHttp {
            calls: AtomicUsize::new(0),
            responses: StdMutex::new(VecDeque::from([
                Ok(response(jwks(Some(X)), "max-age=0")),
                Ok(response(jwks(None), "no-store")),
                Ok(response(jwks(None), "no-store")),
            ])),
            request_headers: StdMutex::new(Vec::new()),
        });
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http.clone(),
            DestinationPolicy::default(),
            high_rate_limits(),
            true,
        )
        .unwrap();
        let key_id = Ed25519Jwk::new(X.into()).b64_thumbprint();
        assert!(matches!(
            service.resolve(request(key_id.clone())).await.unwrap(),
            ResolveResponse::Resolved { .. }
        ));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(matches!(
            service.resolve(request(key_id.clone())).await.unwrap(),
            ResolveResponse::KeyNotFound { .. }
        ));
        assert!(matches!(
            service.resolve(request(key_id)).await.unwrap(),
            ResolveResponse::KeyNotFound { .. }
        ));
        assert_eq!(http.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn conditional_304_reuses_the_parsed_resource() {
        let mut first = response(jwks(Some(X)), "no-cache");
        first
            .headers
            .insert(http::header::ETAG, http::HeaderValue::from_static("\"v1\""));
        let mut not_modified = FetchResponse {
            status: http::StatusCode::NOT_MODIFIED,
            headers: HeaderMap::new(),
            body: Vec::new(),
        };
        not_modified
            .headers
            .insert(http::header::ETAG, http::HeaderValue::from_static("\"v1\""));
        not_modified.headers.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("max-age=60"),
        );
        let http = Arc::new(ScriptedHttp {
            calls: AtomicUsize::new(0),
            responses: StdMutex::new(VecDeque::from([Ok(first), Ok(not_modified)])),
            request_headers: StdMutex::new(Vec::new()),
        });
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http.clone(),
            DestinationPolicy::default(),
            high_rate_limits(),
            true,
        )
        .unwrap();
        let first = service
            .resolve_with_metadata(request("missing".into()))
            .await
            .unwrap();
        assert_eq!(first.cache_valid_for, Duration::ZERO);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let revalidated = service
            .resolve_with_metadata(request("missing".into()))
            .await
            .unwrap();
        assert!(revalidated.cache_valid_for > Duration::from_secs(59));
        service.resolve(request("missing".into())).await.unwrap();
        assert_eq!(http.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            http.request_headers.lock().unwrap()[1]
                .get(http::header::IF_NONE_MATCH)
                .unwrap(),
            "\"v1\""
        );
    }

    #[tokio::test]
    async fn successful_rotation_removes_old_keys_atomically() {
        let http = Arc::new(ScriptedHttp {
            calls: AtomicUsize::new(0),
            responses: StdMutex::new(VecDeque::from([
                Ok(response(jwks(Some(X)), "no-cache")),
                Ok(response(jwks(None), "max-age=60")),
            ])),
            request_headers: StdMutex::new(Vec::new()),
        });
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http,
            DestinationPolicy::default(),
            high_rate_limits(),
            true,
        )
        .unwrap();
        let key_id = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_owned();
        assert!(matches!(
            service.resolve(request(key_id.clone())).await.unwrap(),
            ResolveResponse::Resolved { .. }
        ));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(matches!(
            service.resolve(request(key_id)).await.unwrap(),
            ResolveResponse::KeyNotFound { .. }
        ));
    }

    #[tokio::test]
    async fn stale_if_error_keeps_the_previous_representation() {
        let http = Arc::new(ScriptedHttp {
            calls: AtomicUsize::new(0),
            responses: StdMutex::new(VecDeque::from([
                Ok(response(jwks(Some(X)), "max-age=0, stale-if-error=60")),
                Err(FetchError::new(FetchErrorKind::Transport)),
            ])),
            request_headers: StdMutex::new(Vec::new()),
        });
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http,
            DestinationPolicy::default(),
            high_rate_limits(),
            true,
        )
        .unwrap();
        let key_id = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_owned();
        service.resolve(request(key_id.clone())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let stale = service
            .resolve_with_metadata(request(key_id))
            .await
            .unwrap();
        assert!(matches!(stale.response, ResolveResponse::Resolved { .. }));
        assert_eq!(stale.cache_valid_for, Duration::ZERO);
    }

    #[tokio::test]
    async fn permanent_refresh_errors_do_not_serve_stale_data_or_back_off() {
        let http = Arc::new(ScriptedHttp {
            calls: AtomicUsize::new(0),
            responses: StdMutex::new(VecDeque::from([
                Ok(response(jwks(Some(X)), "max-age=0, stale-if-error=60")),
                Err(FetchError::new(FetchErrorKind::InvalidResource)),
                Err(FetchError::new(FetchErrorKind::InvalidResource)),
            ])),
            request_headers: StdMutex::new(Vec::new()),
        });
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http.clone(),
            DestinationPolicy::default(),
            high_rate_limits(),
            true,
        )
        .unwrap();
        let key_id = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_owned();
        service.resolve(request(key_id.clone())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;

        let first = service.resolve(request(key_id.clone())).await.unwrap_err();
        assert_eq!(first.kind, FetchErrorKind::InvalidResource);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let second = service.resolve(request(key_id)).await.unwrap_err();
        assert_eq!(second.kind, FetchErrorKind::InvalidResource);
        assert_eq!(http.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn official_test_key_is_rejected_without_fetching() {
        let http = Arc::new(FakeHttp {
            calls: AtomicUsize::new(0),
            body: jwks(Some(X)),
        });
        let service = ResolverService::new(
            Arc::new(FakeDns),
            http.clone(),
            DestinationPolicy::default(),
            Limits::default(),
            false,
        )
        .unwrap();
        assert!(matches!(
            service
                .resolve(request(
                    "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".into()
                ))
                .await
                .unwrap(),
            ResolveResponse::KeyNotFound { .. }
        ));
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }
}
