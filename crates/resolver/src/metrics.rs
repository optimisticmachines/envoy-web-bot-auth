//! Fixed-cardinality metrics for resolver request and resource work.

use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram},
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    metrics::{Aggregation, Instrument, PeriodicReader, SdkMeterProvider, Stream},
};
use std::{env, time::Duration};

const INSTRUMENTATION_SCOPE: &str = "web_bot_auth_resolver";
const RESOLUTION_DURATION_METRIC: &str = "web_bot_auth.resolver.resolution.duration";
const FETCH_DURATION_METRIC: &str = "web_bot_auth.resolver.fetch.duration";

// The resolver's bounded deadline is 1.8 seconds. These boundaries retain
// useful resolution for UDS cache hits while making timeout behaviour visible.
const RESOLVER_DURATION_BUCKETS_SECONDS: &[f64] = &[
    0.000_025, 0.000_05, 0.000_1, 0.000_25, 0.000_5, 0.001, 0.002_5, 0.005, 0.01, 0.025, 0.05, 0.1,
    0.25, 0.5, 1.0, 1.8, 2.0,
];

#[derive(Clone)]
pub(crate) struct Metrics {
    resolution_results: Counter<u64>,
    resolution_duration: Histogram<f64>,
    cache_events: Counter<u64>,
    fetch_results: Counter<u64>,
    fetch_duration: Histogram<f64>,
}

impl Metrics {
    pub(crate) fn new() -> Self {
        let meter = global::meter(INSTRUMENTATION_SCOPE);
        Self {
            resolution_results: meter
                .u64_counter("web_bot_auth.resolver.resolutions")
                .with_description("Completed resolver requests by result")
                .with_unit("{request}")
                .build(),
            resolution_duration: meter
                .f64_histogram(RESOLUTION_DURATION_METRIC)
                .with_description("Resolver request duration")
                .with_unit("s")
                .build(),
            cache_events: meter
                .u64_counter("web_bot_auth.resolver.cache.events")
                .with_description("Resource cache events. Refresh events record refresh starts")
                .with_unit("{event}")
                .build(),
            fetch_results: meter
                .u64_counter("web_bot_auth.resolver.fetches")
                .with_description("Completed outbound resource fetches by result")
                .with_unit("{fetch}")
                .build(),
            fetch_duration: meter
                .f64_histogram(FETCH_DURATION_METRIC)
                .with_description("Outbound resource fetch duration")
                .with_unit("s")
                .build(),
        }
    }

    pub(crate) fn resolution(&self, result: &'static str, duration: Duration) {
        let attributes = [KeyValue::new("result", result)];
        self.resolution_results.add(1, &attributes);
        self.resolution_duration
            .record(duration.as_secs_f64(), &attributes);
    }

    pub(crate) fn cache_event(&self, event: &'static str) {
        self.cache_events.add(1, &[KeyValue::new("event", event)]);
    }

    pub(crate) fn fetch(&self, result: &'static str, duration: Duration) {
        let attributes = [KeyValue::new("result", result)];
        self.fetch_results.add(1, &attributes);
        self.fetch_duration
            .record(duration.as_secs_f64(), &attributes);
    }
}

pub(crate) fn resolution_result(
    result: &Result<crate::service::Resolution, crate::FetchError>,
) -> &'static str {
    match result {
        Ok(crate::service::Resolution {
            response: web_bot_auth_protocol::ResolveResponse::Resolved { .. },
            ..
        }) => "resolved",
        Ok(crate::service::Resolution {
            response: web_bot_auth_protocol::ResolveResponse::KeyNotFound { .. },
            ..
        }) => "key_not_found",
        Err(error) => error.kind.as_str(),
    }
}

pub(crate) fn fetch_result(result: Result<(), crate::FetchErrorKind>) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(kind) => kind.as_str(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetricsExporterState {
    Disabled,
    Enabled,
    InvalidEndpoint,
}

/// Configures a background OTLP gRPC exporter when an endpoint is explicit.
///
/// The provider is intentionally not installed by default. Metric recording
/// remains non-blocking when it is disabled or exporter setup fails.
pub fn initialize_metrics_exporter() -> MetricsExporterState {
    let Some(endpoint) = exporter_endpoint_from_env() else {
        return MetricsExporterState::Disabled;
    };

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build();
    let Ok(exporter) = exporter else {
        return MetricsExporterState::InvalidEndpoint;
    };
    let reader = PeriodicReader::builder(exporter)
        .with_interval(export_interval_from_env())
        .build();
    let provider = SdkMeterProvider::builder()
        .with_resource(
            Resource::builder()
                .with_service_name("web-bot-auth-resolver")
                .build(),
        )
        .with_reader(reader)
        .with_view(resolver_duration_histogram_view)
        .build();
    global::set_meter_provider(provider);
    MetricsExporterState::Enabled
}

fn resolver_duration_histogram_view(instrument: &Instrument) -> Option<Stream> {
    matches!(
        instrument.name(),
        RESOLUTION_DURATION_METRIC | FETCH_DURATION_METRIC
    )
    .then(|| {
        Stream::builder()
            .with_aggregation(Aggregation::ExplicitBucketHistogram {
                boundaries: RESOLVER_DURATION_BUCKETS_SECONDS.to_vec(),
                record_min_max: false,
            })
            .build()
            .expect("resolver duration histogram boundaries are valid")
    })
}

fn exporter_endpoint_from_env() -> Option<String> {
    [
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
    ]
    .into_iter()
    .find_map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
}

fn export_interval_from_env() -> Duration {
    env::var("OTEL_METRIC_EXPORT_INTERVAL")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|milliseconds| *milliseconds > 0)
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(5))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_duration_histogram_boundaries_cover_cache_hits_and_deadline() {
        assert_eq!(RESOLVER_DURATION_BUCKETS_SECONDS.first(), Some(&0.000_025));
        assert!(
            RESOLVER_DURATION_BUCKETS_SECONDS
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(RESOLVER_DURATION_BUCKETS_SECONDS.contains(&1.8));
        assert!(RESOLVER_DURATION_BUCKETS_SECONDS.len() <= 20);
    }
}
