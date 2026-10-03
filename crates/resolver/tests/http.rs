use async_trait::async_trait;
use axum::{Router, body::Body, http::Request, response::Response};
use http::{HeaderMap, HeaderValue, StatusCode};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;
use tower::ServiceExt;
use web_bot_auth_protocol::{
    CACHE_VALID_FOR_HEADER, DiscoveryMechanism, Ed25519Jwk, MAX_RESOLVE_BODY_BYTES, ResolveRequest,
    ResolveResponse, ResolverApiVersion,
};
use web_bot_auth_resolver::{
    DestinationPolicy, DnsResolver, FetchError, FetchErrorKind, FetchRequest, FetchResponse,
    HttpFetcher, Limits, ResolverService,
};

struct LoopbackDns;

#[async_trait]
impl DnsResolver for LoopbackDns {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, FetchError> {
        Ok(vec!["8.8.8.8".parse().unwrap()])
    }
}

struct FixtureHttp {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpFetcher for FixtureHttp {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwk-set+json"),
        );
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=300"),
        );
        let body = if request.url.query() == Some("generation=2") {
            format!(
                r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{}"}}]}}"#,
                TEST_X
            )
        } else {
            r#"{"keys":[]}"#.to_owned()
        };
        Ok(FetchResponse {
            status: StatusCode::OK,
            headers,
            body: body.into_bytes(),
        })
    }
}

const TEST_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

fn request(agent_url: &str, key_id: &str) -> ResolveRequest {
    ResolveRequest {
        api_version: ResolverApiVersion::V1,
        discovery: DiscoveryMechanism::JwksUri,
        agent_url: agent_url.to_owned(),
        key_id: key_id.to_owned(),
    }
}

fn request_body(request: &ResolveRequest) -> Vec<u8> {
    serde_json::to_vec(request).expect("test request serializes")
}

async fn post(router: &Router, body: Vec<u8>) -> Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/resolve")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("test request builds"),
        )
        .await
        .expect("router responds")
}

fn resolver(http: Arc<dyn HttpFetcher>, limits: web_bot_auth_resolver::Limits) -> ResolverService {
    ResolverService::new(
        Arc::new(LoopbackDns),
        http,
        DestinationPolicy::default(),
        limits,
        true,
    )
    .expect("test resolver configuration is valid")
}

fn response_headers(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=300"),
    );
    headers
}

struct FailingHttp {
    kind: FetchErrorKind,
}

#[async_trait]
impl HttpFetcher for FailingHttp {
    async fn fetch(&self, _request: FetchRequest) -> Result<FetchResponse, FetchError> {
        Err(FetchError {
            kind: self.kind,
            status: None,
            retry_after: None,
        })
    }
}

struct MalformedResourceHttp;

#[async_trait]
impl HttpFetcher for MalformedResourceHttp {
    async fn fetch(&self, _request: FetchRequest) -> Result<FetchResponse, FetchError> {
        Ok(FetchResponse {
            status: StatusCode::OK,
            headers: response_headers("application/jwk-set+json"),
            body: br#"{"keys":["not a JWK"]}"#.to_vec(),
        })
    }
}

struct CimdHttp {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpFetcher for CimdHttp {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (content_type, body) = match request.kind {
            web_bot_auth_resolver::ResourceKind::Cimd => (
                "application/json",
                format!(
                    r#"{{"client_id":"{}","jwks_uri":"https://keys.example/jwks"}}"#,
                    request.url
                )
                .into_bytes(),
            ),
            web_bot_auth_resolver::ResourceKind::Jwks => (
                "application/jwk-set+json",
                format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{TEST_X}"}}]}}"#)
                    .into_bytes(),
            ),
        };
        Ok(FetchResponse {
            status: StatusCode::OK,
            headers: response_headers(content_type),
            body,
        })
    }
}

struct BlockingHttp {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait]
impl HttpFetcher for BlockingHttp {
    async fn fetch(&self, _request: FetchRequest) -> Result<FetchResponse, FetchError> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(FetchResponse {
            status: StatusCode::OK,
            headers: response_headers("application/jwk-set+json"),
            body: format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{TEST_X}"}}]}}"#)
                .into_bytes(),
        })
    }
}

#[tokio::test]
async fn real_http_router_preserves_query_for_fetch_and_not_identity() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = resolver(
        Arc::new(FixtureHttp {
            calls: Arc::clone(&calls),
        }),
        Limits::default(),
    );
    let router = web_bot_auth_resolver::server::router(resolver);
    let jwk = Ed25519Jwk::new(TEST_X.to_owned());
    let response = post(
        &router,
        request_body(&request(
            "https://agent.example/keys?generation=2#ignored",
            &jwk.b64_thumbprint(),
        )),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cache_valid_for = response
        .headers()
        .get(CACHE_VALID_FOR_HEADER)
        .expect("fresh response advertises module cache freshness")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!((1..=300_000).contains(&cache_valid_for));
    let body = axum::body::to_bytes(response.into_body(), 8 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["normalized_identifier"], "https://agent.example/keys");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn real_http_router_maps_malformed_json_and_request_to_bad_request() {
    let router = web_bot_auth_resolver::server::router(resolver(
        Arc::new(FixtureHttp {
            calls: Arc::new(AtomicUsize::new(0)),
        }),
        web_bot_auth_resolver::Limits::default(),
    ));

    assert_eq!(
        post(&router, b"{".to_vec()).await.status(),
        StatusCode::BAD_REQUEST
    );
    let invalid = request_body(&ResolveRequest {
        api_version: ResolverApiVersion::V1,
        discovery: DiscoveryMechanism::JwksUri,
        agent_url: "http://agent.example/keys".to_owned(),
        key_id: "key".to_owned(),
    });
    assert_eq!(
        post(&router, invalid).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn real_http_router_rejects_body_over_the_wire_limit() {
    let router = web_bot_auth_resolver::server::router(resolver(
        Arc::new(FixtureHttp {
            calls: Arc::new(AtomicUsize::new(0)),
        }),
        web_bot_auth_resolver::Limits::default(),
    ));
    let body = vec![b'x'; MAX_RESOLVE_BODY_BYTES + 1];
    assert_eq!(
        post(&router, body).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn real_http_router_maps_resource_failures_to_unavailable() {
    let unavailable = web_bot_auth_resolver::server::router(resolver(
        Arc::new(FailingHttp {
            kind: FetchErrorKind::Transport,
        }),
        web_bot_auth_resolver::Limits::default(),
    ));
    let unavailable_response = post(
        &unavailable,
        request_body(&request("https://agent.example/keys", "unknown")),
    )
    .await;
    assert_eq!(
        unavailable_response.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let malformed = web_bot_auth_resolver::server::router(resolver(
        Arc::new(MalformedResourceHttp),
        web_bot_auth_resolver::Limits::default(),
    ));
    let malformed_response = post(
        &malformed,
        request_body(&request("https://agent.example/keys", "unknown")),
    )
    .await;
    assert_eq!(malformed_response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn real_http_router_returns_missing_key_and_reuses_a_fresh_cache() {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = web_bot_auth_resolver::server::router(resolver(
        Arc::new(FixtureHttp {
            calls: Arc::clone(&calls),
        }),
        web_bot_auth_resolver::Limits::default(),
    ));
    let body = request_body(&request(
        "https://agent.example/keys?generation=2",
        "unknown",
    ));
    let first = post(&router, body.clone()).await;
    let second = post(&router, body).await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    let first_body = axum::body::to_bytes(first.into_body(), 8 * 1024)
        .await
        .unwrap();
    let parsed: ResolveResponse = serde_json::from_slice(&first_body).unwrap();
    assert!(matches!(parsed, ResolveResponse::KeyNotFound { .. }));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn real_http_router_limits_cimd_to_metadata_and_one_key_fetch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = web_bot_auth_resolver::server::router(resolver(
        Arc::new(CimdHttp {
            calls: Arc::clone(&calls),
        }),
        web_bot_auth_resolver::Limits::default(),
    ));
    let jwk = Ed25519Jwk::new(TEST_X.to_owned());
    let body = request_body(&ResolveRequest {
        api_version: ResolverApiVersion::V1,
        discovery: DiscoveryMechanism::Cimd,
        agent_url: "https://agent.example/metadata".to_owned(),
        key_id: jwk.b64_thumbprint(),
    });
    let response = post(&router, body.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = post(&router, body).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn real_http_router_sheds_a_second_active_handler_immediately() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let limits = web_bot_auth_resolver::Limits {
        active_handlers: 1,
        ..web_bot_auth_resolver::Limits::default()
    };
    let router = web_bot_auth_resolver::server::router(resolver(
        Arc::new(BlockingHttp {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        }),
        limits,
    ));
    let body = request_body(&request("https://agent.example/keys", "unknown"));
    let first = tokio::spawn({
        let router = router.clone();
        let body = body.clone();
        async move { post(&router, body).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
        .await
        .expect("first request entered the fetcher");
    let second = post(&router, body).await;
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    release.notify_one();
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
}
