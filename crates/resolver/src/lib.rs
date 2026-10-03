//! Bounded Web Bot Auth discovery resolver and its HTTP boundary.

mod cache;
mod controls;
mod fetch;
#[cfg(feature = "kind-fixtures")]
mod fixture;
mod loader;
mod metrics;
mod resource;
pub mod server;
mod service;
mod ssrf;

pub use controls::Limits;
pub use fetch::{
    DnsResolver, EgressMode, FetchError, FetchErrorKind, FetchRequest, FetchResponse, HttpFetcher,
    ProductionDns, ReqwestFetcher, ResourceKind,
};
#[cfg(feature = "kind-fixtures")]
pub use fixture::{FIXTURE_AGENT_URL, FixtureMode, FixtureTransport};
pub use metrics::{MetricsExporterState, initialize_metrics_exporter};
pub use service::{Resolution, ResolverService};
pub use ssrf::DestinationPolicy;
pub use web_bot_auth_protocol as protocol;
