mod listener;

#[cfg(any(feature = "kind-fixtures", test))]
use axum::Router;
#[cfg(feature = "kind-fixtures")]
use axum::{
    Json,
    extract::{DefaultBodyLimit, State},
    response::IntoResponse,
    routing::post,
};
#[cfg(any(feature = "kind-fixtures", test))]
use axum::{http::StatusCode, routing::get};
use clap::{Args, Parser, Subcommand, ValueEnum};
use listener::{ListenAddress, ProbeArgs, probe, serve_app};
#[cfg(test)]
use listener::{prepare_socket_path, remove_own_socket};
#[cfg(feature = "kind-fixtures")]
use std::path::PathBuf;
use std::{env, ffi::OsString, sync::Arc, time::Duration};
#[cfg(feature = "kind-fixtures")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "kind-fixtures")]
use tokio::sync::RwLock;
#[cfg(feature = "kind-fixtures")]
use web_bot_auth_protocol::ResolveRequest;
#[cfg(feature = "kind-fixtures")]
use web_bot_auth_resolver::FetchErrorKind;
use web_bot_auth_resolver::{
    DestinationPolicy, EgressMode, Limits, ProductionDns, ReqwestFetcher, ResolverService,
};

#[cfg(feature = "kind-fixtures")]
use web_bot_auth_resolver::{FixtureMode, FixtureTransport};

#[derive(Debug, Parser)]
#[command(name = "web-bot-auth-resolver")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve(ServeArgs),
    #[cfg(feature = "kind-fixtures")]
    ServeFixtures(ServeArgs),
    #[cfg(feature = "kind-fixtures")]
    FixtureControl(FixtureControlArgs),
    Probe(ProbeArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EgressArg {
    Direct,
    Proxy,
}

#[derive(Debug, Args)]
struct ServeArgs {
    #[arg(
        long,
        default_value = "tcp://127.0.0.1:8081",
        help = "Listen on tcp://IP:PORT or unix:///absolute/path. Non loopback TCP exposes the unauthenticated resolver API"
    )]
    listen: String,
    #[arg(long, value_enum, default_value_t = EgressArg::Direct)]
    egress_mode: EgressArg,
    #[arg(long, default_values_t = [443u16])]
    allowed_port: Vec<u16>,
    #[arg(long)]
    allow_test_keys: bool,
    #[arg(long, default_value_t = 8 * 1024, help = "Maximum JSON body size in bytes")]
    inbound_body_bytes: usize,
    #[arg(long, default_value_t = 64, help = "Maximum active resolver handlers")]
    active_handlers: usize,
    #[arg(long, default_value_t = 32, help = "Maximum active remote fetches")]
    outbound_fetches: usize,
    #[arg(long, default_value_t = 16, help = "Global remote fetches per second")]
    global_fetch_rate: u32,
    #[arg(long, default_value_t = 32, help = "Global remote fetch burst")]
    global_fetch_burst: u32,
    #[arg(
        long,
        default_value_t = 2,
        help = "Remote fetches per origin per second"
    )]
    origin_fetch_rate: u32,
    #[arg(long, default_value_t = 4, help = "Remote fetch burst per origin")]
    origin_fetch_burst: u32,
    #[arg(
        long,
        default_value_t = 8,
        help = "Remote fetches per address per second"
    )]
    ip_fetch_rate: u32,
    #[arg(long, default_value_t = 16, help = "Remote fetch burst per address")]
    ip_fetch_burst: u32,
    #[arg(long, default_value_t = 256, help = "New origins allowed per minute")]
    new_origins_per_minute: usize,
    #[arg(
        long,
        default_value_t = 1_024,
        help = "Maximum entries in each cache and control store"
    )]
    state_entries: u64,
    #[arg(
        long,
        default_value_t = 32,
        help = "Maximum keys from one JWKS response"
    )]
    max_keys: usize,
    #[arg(
        long,
        default_value_t = 1_800,
        help = "Maximum full resolution time in milliseconds"
    )]
    resolution_timeout_ms: u64,
}

/// Available only in the fixture image compiled with the `kind-fixtures` feature.
#[cfg(feature = "kind-fixtures")]
#[derive(Debug, Args)]
struct FixtureControlArgs {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long, value_enum)]
    mode: FixtureModeArg,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    reset: bool,
    #[arg(long, default_value_t = 250)]
    timeout_ms: u64,
}

#[cfg(feature = "kind-fixtures")]
#[derive(Clone, Copy, Debug, ValueEnum)]
enum FixtureModeArg {
    HealthyV1,
    CacheableV1,
    RotatedV2,
    Malformed,
    Unavailable,
    Delayed,
}

#[cfg(feature = "kind-fixtures")]
impl From<FixtureModeArg> for FixtureMode {
    fn from(value: FixtureModeArg) -> Self {
        match value {
            FixtureModeArg::HealthyV1 => Self::HealthyV1,
            FixtureModeArg::CacheableV1 => Self::CacheableV1,
            FixtureModeArg::RotatedV2 => Self::RotatedV2,
            FixtureModeArg::Malformed => Self::Malformed,
            FixtureModeArg::Unavailable => Self::Unavailable,
            FixtureModeArg::Delayed => Self::Delayed,
        }
    }
}

#[cfg(feature = "kind-fixtures")]
#[derive(Clone)]
struct FixtureAppState {
    resolver: Arc<RwLock<ResolverService>>,
    fixture: FixtureTransport,
    limits: Limits,
}

#[derive(Clone, Debug, Default)]
struct ProxyEnvironment {
    https_proxy: Option<OsString>,
    https_proxy_lower: Option<OsString>,
    http_proxy: Option<OsString>,
    http_proxy_lower: Option<OsString>,
    all_proxy: Option<OsString>,
    all_proxy_lower: Option<OsString>,
}

impl ProxyEnvironment {
    fn from_process() -> Self {
        Self {
            https_proxy: env::var_os("HTTPS_PROXY"),
            https_proxy_lower: env::var_os("https_proxy"),
            http_proxy: env::var_os("HTTP_PROXY"),
            http_proxy_lower: env::var_os("http_proxy"),
            all_proxy: env::var_os("ALL_PROXY"),
            all_proxy_lower: env::var_os("all_proxy"),
        }
    }

    fn has_any(&self) -> bool {
        self.https_proxy.is_some()
            || self.https_proxy_lower.is_some()
            || self.http_proxy.is_some()
            || self.http_proxy_lower.is_some()
            || self.all_proxy.is_some()
            || self.all_proxy_lower.is_some()
    }

    fn has_non_https_proxy(&self) -> bool {
        self.http_proxy.is_some()
            || self.http_proxy_lower.is_some()
            || self.all_proxy.is_some()
            || self.all_proxy_lower.is_some()
    }
}

#[tokio::main]
async fn main() {
    let result = match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        #[cfg(feature = "kind-fixtures")]
        Command::ServeFixtures(args) => serve_fixtures(args).await,
        #[cfg(feature = "kind-fixtures")]
        Command::FixtureControl(args) => fixture_control(args).await,
        Command::Probe(args) => probe(args).await,
    };
    if let Err(reason) = result {
        eprintln!("resolver event={reason}");
        std::process::exit(1);
    }
}

async fn serve(args: ServeArgs) -> Result<(), &'static str> {
    report_metrics_exporter();
    let limits = limits(&args);
    limits.validate()?;
    let destination_policy =
        DestinationPolicy::new(std::iter::once(443).chain(args.allowed_port.iter().copied()))?;
    let (mode, fetcher) = production_fetcher(
        args.egress_mode,
        &ProxyEnvironment::from_process(),
        limits.resolution_timeout,
    )?;
    let resolver = ResolverService::new(
        Arc::new(ProductionDns),
        Arc::new(fetcher),
        destination_policy,
        limits.clone(),
        args.allow_test_keys,
    )?;
    let app = web_bot_auth_resolver::server::router(resolver);

    let listen = ListenAddress::parse(&args.listen)?;
    warn_if_network_exposed(&listen);
    eprintln!(
        "resolver event=startup transport={} egress={mode:?} handlers={} fetches={} state_entries={} allow_test_keys={}",
        listen.kind(),
        limits.active_handlers,
        limits.outbound_fetches,
        limits.state_entries,
        args.allow_test_keys,
    );
    serve_app(listen, app).await
}

fn limits(args: &ServeArgs) -> Limits {
    Limits {
        inbound_body_bytes: args.inbound_body_bytes,
        active_handlers: args.active_handlers,
        outbound_fetches: args.outbound_fetches,
        global_fetch_rate: args.global_fetch_rate,
        global_fetch_burst: args.global_fetch_burst,
        origin_fetch_rate: args.origin_fetch_rate,
        origin_fetch_burst: args.origin_fetch_burst,
        ip_fetch_rate: args.ip_fetch_rate,
        ip_fetch_burst: args.ip_fetch_burst,
        new_origins_per_minute: args.new_origins_per_minute,
        state_entries: args.state_entries,
        max_keys: args.max_keys,
        resolution_timeout: Duration::from_millis(args.resolution_timeout_ms),
    }
}

#[cfg(feature = "kind-fixtures")]
async fn serve_fixtures(args: ServeArgs) -> Result<(), &'static str> {
    report_metrics_exporter();
    let limits = limits(&args);
    limits.validate()?;
    let fixture = FixtureTransport::new();
    let resolver = ResolverService::new(
        Arc::new(fixture.clone()),
        Arc::new(fixture.clone()),
        DestinationPolicy::default(),
        limits.clone(),
        true,
    )?;
    let app = app_with_fixture(resolver, fixture, limits.clone());
    let listen = ListenAddress::parse(&args.listen)?;
    warn_if_network_exposed(&listen);
    eprintln!(
        "resolver event=startup transport={} egress=fixture handlers={} fetches={} state_entries={}",
        listen.kind(),
        limits.active_handlers,
        limits.outbound_fetches,
        limits.state_entries,
    );
    serve_app(listen, app).await
}

fn report_metrics_exporter() {
    match web_bot_auth_resolver::initialize_metrics_exporter() {
        web_bot_auth_resolver::MetricsExporterState::Disabled => {}
        web_bot_auth_resolver::MetricsExporterState::Enabled => {
            eprintln!("resolver event=metrics_exporter_enabled transport=otlp_grpc");
        }
        web_bot_auth_resolver::MetricsExporterState::InvalidEndpoint => {
            eprintln!("resolver event=metrics_exporter_disabled reason=invalid_endpoint");
        }
    }
}

fn warn_if_network_exposed(listen: &ListenAddress) {
    if let Some(address) = listen.exposed_tcp_address() {
        eprintln!("resolver event=network_listener_exposed address={address} authentication=none");
    }
}

#[cfg(feature = "kind-fixtures")]
fn app_with_fixture(
    resolver: ResolverService,
    fixture: FixtureTransport,
    limits: Limits,
) -> Router {
    let body_limit = resolver.inbound_body_limit();
    Router::new()
        .route("/v1/resolve", post(resolve_fixture))
        .route("/v1/fixture", post(configure_fixture))
        .route("/healthz", get(health))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(FixtureAppState {
            resolver: Arc::new(RwLock::new(resolver)),
            fixture,
            limits,
        })
}

#[cfg(feature = "kind-fixtures")]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct FixtureControlRequest {
    mode: FixtureMode,
    #[serde(default)]
    reset: bool,
}

#[cfg(feature = "kind-fixtures")]
async fn configure_fixture(
    State(state): State<FixtureAppState>,
    Json(request): Json<FixtureControlRequest>,
) -> impl IntoResponse {
    state.fixture.set_mode(request.mode).await;
    if request.reset {
        let replacement = ResolverService::new(
            Arc::new(state.fixture.clone()),
            Arc::new(state.fixture.clone()),
            DestinationPolicy::default(),
            state.limits.clone(),
            true,
        );
        match replacement {
            Ok(replacement) => *state.resolver.write().await = replacement,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

fn production_fetcher(
    mode: EgressArg,
    environment: &ProxyEnvironment,
    timeout: Duration,
) -> Result<(EgressMode, ReqwestFetcher), &'static str> {
    match mode {
        EgressArg::Direct => {
            if environment.has_any() {
                return Err("direct_mode_proxy_conflict");
            }
            Ok((EgressMode::Direct, ReqwestFetcher::direct(timeout)))
        }
        EgressArg::Proxy => {
            if environment.has_non_https_proxy() {
                return Err("proxy_mode_variable_conflict");
            }
            let proxy = environment
                .https_proxy
                .as_ref()
                .and_then(|value| value.to_str())
                .filter(|value| !value.is_empty())
                .ok_or("proxy_mode_requires_https_proxy")?;
            if environment
                .https_proxy_lower
                .as_ref()
                .is_some_and(|lower| lower != proxy)
            {
                return Err("proxy_mode_variable_conflict");
            }
            Ok((EgressMode::Proxy, ReqwestFetcher::proxy(proxy, timeout)?))
        }
    }
}

#[cfg(feature = "kind-fixtures")]
async fn resolve_fixture(
    State(state): State<FixtureAppState>,
    Json(request): Json<ResolveRequest>,
) -> impl IntoResponse {
    let resolver = state.resolver.read().await.clone();
    match resolver.resolve_with_metadata(request).await {
        Ok(resolution) => web_bot_auth_resolver::server::resolution_response(resolution),
        Err(error) if error.kind == FetchErrorKind::BadRequest => {
            (StatusCode::BAD_REQUEST, "invalid resolver request\n").into_response()
        }
        Err(error) => {
            eprintln!(
                "resolver event=resolution_failure reason={}",
                error.kind.as_str()
            );
            (StatusCode::SERVICE_UNAVAILABLE, "resolution unavailable\n").into_response()
        }
    }
}

#[cfg(any(feature = "kind-fixtures", test))]
async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[cfg(feature = "kind-fixtures")]
async fn fixture_control(args: FixtureControlArgs) -> Result<(), &'static str> {
    let mode: FixtureMode = args.mode.into();
    let body = serde_json::to_vec(&FixtureControlRequest {
        mode,
        reset: args.reset,
    })
    .map_err(|_| "fixture_control_encoding_failed")?;
    let operation = async {
        let mut stream = tokio::net::UnixStream::connect(&args.socket)
            .await
            .map_err(|_| "fixture_control_connect_failed")?;
        let request = format!(
            "POST /v1/fixture HTTP/1.1\r\nHost: resolver\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| "fixture_control_write_failed")?;
        stream
            .write_all(&body)
            .await
            .map_err(|_| "fixture_control_write_failed")?;
        let mut response = [0u8; 128];
        let read = stream
            .read(&mut response)
            .await
            .map_err(|_| "fixture_control_read_failed")?;
        if !response[..read].starts_with(b"HTTP/1.1 204") {
            return Err("fixture_control_rejected");
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_millis(args.timeout_ms), operation)
        .await
        .map_err(|_| "fixture_control_timeout")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    static SOCKET_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    #[test]
    fn parses_transport_neutral_listeners() {
        assert!(matches!(
            ListenAddress::parse("tcp://127.0.0.1:8081"),
            Ok(ListenAddress::Tcp(_))
        ));
        assert!(matches!(
            ListenAddress::parse("unix:///run/wba/resolver.sock"),
            Ok(ListenAddress::Unix(_))
        ));
        assert!(ListenAddress::parse("0.0.0.0:8081").is_err());
        assert!(matches!(
            ListenAddress::parse("tcp://0.0.0.0:8081"),
            Ok(ListenAddress::Tcp(_))
        ));
        assert!(matches!(
            ListenAddress::parse("tcp://192.0.2.1:8081"),
            Ok(ListenAddress::Tcp(_))
        ));
        assert!(matches!(
            ListenAddress::parse("tcp://[::1]:8081"),
            Ok(ListenAddress::Tcp(_))
        ));
    }

    #[test]
    fn identifies_network_exposed_tcp_listeners() {
        let loopback = ListenAddress::parse("tcp://127.0.0.1:8081").unwrap();
        let exposed = ListenAddress::parse("tcp://0.0.0.0:8081").unwrap();
        let unix = ListenAddress::parse("unix:///run/wba/resolver.sock").unwrap();

        assert_eq!(loopback.exposed_tcp_address(), None);
        assert_eq!(
            exposed.exposed_tcp_address(),
            Some("0.0.0.0:8081".parse().unwrap())
        );
        assert_eq!(unix.exposed_tcp_address(), None);
    }

    #[test]
    fn proxy_modes_reject_conflicting_environment_values() {
        let empty = ProxyEnvironment::default();
        assert!(production_fetcher(EgressArg::Direct, &empty, Duration::from_secs(1)).is_ok());
        assert!(matches!(
            production_fetcher(EgressArg::Proxy, &empty, Duration::from_secs(1)),
            Err("proxy_mode_requires_https_proxy")
        ));

        let proxy = ProxyEnvironment {
            https_proxy: Some("https://proxy.example:8443".into()),
            ..ProxyEnvironment::default()
        };
        assert!(matches!(
            production_fetcher(EgressArg::Direct, &proxy, Duration::from_secs(1)),
            Err("direct_mode_proxy_conflict")
        ));
        assert!(production_fetcher(EgressArg::Proxy, &proxy, Duration::from_secs(1)).is_ok());

        let conflict = ProxyEnvironment {
            https_proxy: Some("https://proxy.example:8443".into()),
            https_proxy_lower: Some("https://other.example:8443".into()),
            ..ProxyEnvironment::default()
        };
        assert!(matches!(
            production_fetcher(EgressArg::Proxy, &conflict, Duration::from_secs(1)),
            Err("proxy_mode_variable_conflict")
        ));
    }

    #[tokio::test]
    #[ignore = "requires Unix domain socket support"]
    async fn stale_socket_is_removed_but_files_and_symlinks_are_rejected() {
        let _lock = SOCKET_TEST_LOCK.lock().await;
        let directory = unique_test_directory("lifecycle");
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("resolver.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        drop(listener);
        prepare_socket_path(&socket).unwrap();
        assert!(!socket.exists());

        std::fs::write(&socket, b"not a socket").unwrap();
        assert_eq!(prepare_socket_path(&socket), Err("socket_path_not_socket"));
        std::fs::remove_file(&socket).unwrap();
        symlink("missing", &socket).unwrap();
        assert_eq!(prepare_socket_path(&socket), Err("socket_path_not_socket"));
        std::fs::remove_file(&socket).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Unix domain socket support"]
    async fn native_probe_reaches_uds_health_endpoint_with_expected_permissions() {
        let _lock = SOCKET_TEST_LOCK.lock().await;
        let directory = unique_test_directory("probe");
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("resolver.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/healthz", get(health)))
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        probe(ProbeArgs {
            socket: socket.clone(),
            timeout_ms: 250,
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&socket)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o660,
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        remove_own_socket(&socket).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(feature = "kind-fixtures")]
    #[tokio::test]
    #[ignore = "requires Unix domain socket support"]
    async fn fixture_control_updates_the_fixture_over_uds() {
        let _lock = SOCKET_TEST_LOCK.lock().await;
        let directory = unique_test_directory("fixture-control");
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("resolver.sock");
        let fixture = FixtureTransport::new();
        let observed_fixture = fixture.clone();
        let resolver = ResolverService::new(
            Arc::new(fixture.clone()),
            Arc::new(fixture.clone()),
            DestinationPolicy::default(),
            Limits::default(),
            true,
        )
        .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app_with_fixture(resolver, fixture, Limits::default()),
            )
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        fixture_control(FixtureControlArgs {
            socket: socket.clone(),
            mode: FixtureModeArg::RotatedV2,
            reset: true,
            timeout_ms: 250,
        })
        .await
        .unwrap();
        assert_eq!(observed_fixture.mode().await, FixtureMode::RotatedV2);
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        std::fs::remove_file(&socket).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    fn unique_test_directory(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("wba-socket-{label}-{}-{nonce}", std::process::id()))
    }
}
