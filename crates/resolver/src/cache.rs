//! Cache policy, refresh coalescing, and atomic representation publication.

use super::{
    fetch::{FetchError, FetchErrorKind, FetchResponse, ResourceKind},
    loader::ResourceLoader,
    metrics::Metrics,
    resource::{ParsedResource, parse_resource},
};
use http::{HeaderMap, Request, Response};
use http_cache_semantics::{AfterResponse, BeforeRequest, CacheOptions, CachePolicy};
use moka::future::Cache;
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use url::Url;

const MAX_FRESHNESS: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct ResourceKey {
    pub(super) url: Url,
    pub(super) kind: ResourceKind,
}

#[derive(Clone, Debug)]
pub(super) struct Representation {
    pub(super) resource: ParsedResource,
    pub(super) policy: CachePolicy,
    stored_at: SystemTime,
    fresh_for: Duration,
    fresh_until: Instant,
    stale_if_error: Option<Duration>,
}

impl Representation {
    pub(super) fn fresh_request(
        &self,
        request: &Request<()>,
        now: SystemTime,
        monotonic_now: Instant,
    ) -> Option<HeaderMap> {
        if monotonic_now >= self.fresh_until
            || now.duration_since(self.stored_at).unwrap_or(Duration::ZERO) >= MAX_FRESHNESS
        {
            return None;
        }
        match self.policy.before_request(request, now) {
            BeforeRequest::Fresh(parts) => Some(parts.headers),
            BeforeRequest::Stale { .. } => None,
        }
    }

    pub(super) fn stale_allowed_after_error(&self, now: SystemTime) -> bool {
        let Some(stale_for) = self.stale_if_error else {
            return false;
        };
        now.duration_since(self.stored_at)
            .ok()
            .is_some_and(|age| age <= self.fresh_for.saturating_add(stale_for))
    }

    /// Returns freshness which another cache may safely reuse.
    ///
    /// Stale and non storable representations deliberately return zero. This
    /// keeps all HTTP cache policy interpretation inside the resolver.
    pub(super) fn remaining_freshness(&self, now: Instant) -> Duration {
        if !self.policy.is_storable() {
            return Duration::ZERO;
        }
        self.fresh_until.saturating_duration_since(now)
    }
}

#[derive(Clone, Debug)]
pub(super) struct RefreshOutcome {
    pub(super) result: Result<Arc<Representation>, FetchError>,
    pub(super) valid_until: Instant,
}

#[derive(Clone)]
pub(super) struct CacheStore {
    representations: Cache<ResourceKey, Arc<Representation>>,
    refreshes: Cache<ResourceKey, Arc<RefreshOutcome>>,
    metrics: Metrics,
}

impl CacheStore {
    pub(super) fn new(state_entries: u64, refresh_ttl: Duration, metrics: Metrics) -> Self {
        Self {
            representations: Cache::builder().max_capacity(state_entries).build(),
            refreshes: Cache::builder()
                .max_capacity(state_entries)
                .time_to_live(refresh_ttl)
                .build(),
            metrics,
        }
    }

    pub(super) async fn load(
        &self,
        loader: &ResourceLoader,
        key: ResourceKey,
    ) -> Result<Arc<Representation>, FetchError> {
        let request = cache_request(&key)?;
        let now = SystemTime::now();
        let monotonic_now = Instant::now();
        let previous = self.representations.get(&key).await;
        if previous
            .as_ref()
            .and_then(|representation| representation.fresh_request(&request, now, monotonic_now))
            .is_some()
        {
            self.metrics.cache_event("fresh_hit");
            return Ok(previous.expect("checked as present"));
        }

        if let Some(outcome) = self.refreshes.get(&key).await {
            if outcome.valid_until > Instant::now() {
                return self.result_or_stale(&outcome.result, previous, now);
            }
            self.refreshes.invalidate(&key).await;
        }

        let refresh_loader = loader.clone();
        let refresh_key = key.clone();
        let prior = previous.clone();
        let outcome = self
            .refreshes
            .get_with(key.clone(), async move {
                Arc::new(refresh_loader.refresh(refresh_key, prior).await)
            })
            .await;
        self.result_or_stale(&outcome.result, previous, now)
    }

    fn result_or_stale(
        &self,
        result: &Result<Arc<Representation>, FetchError>,
        previous: Option<Arc<Representation>>,
        now: SystemTime,
    ) -> Result<Arc<Representation>, FetchError> {
        match result {
            Ok(representation) => Ok(Arc::clone(representation)),
            Err(error)
                if previous.as_ref().is_some_and(|old| {
                    error.allows_stale() && old.stale_allowed_after_error(now)
                }) =>
            {
                self.metrics.cache_event("stale_on_error");
                Ok(previous.expect("checked as present"))
            }
            Err(error) => {
                self.metrics.cache_event("error");
                Err(error.clone())
            }
        }
    }

    pub(super) async fn publish(&self, key: &ResourceKey, representation: Arc<Representation>) {
        if representation.policy.is_storable() {
            self.representations
                .insert(key.clone(), representation)
                .await;
        } else {
            self.representations.invalidate(key).await;
        }
    }
}

pub(super) fn representation_from_response(
    key: &ResourceKey,
    request: Request<()>,
    previous: Option<Arc<Representation>>,
    mut response: FetchResponse,
    max_keys: usize,
) -> Result<Arc<Representation>, FetchError> {
    let now = SystemTime::now();
    let monotonic_now = Instant::now();
    if response.status == http::StatusCode::NOT_MODIFIED {
        let previous = previous.ok_or_else(|| FetchError::new(FetchErrorKind::InvalidResource))?;
        let response_meta = response_from_fetch(&response)?;
        let (policy, fresh_for, stale_if_error) =
            match previous
                .policy
                .after_response(&request, &response_meta, now)
            {
                AfterResponse::NotModified(policy, _) => {
                    let fresh_for = policy.time_to_live(now).min(MAX_FRESHNESS);
                    let stale_if_error =
                        parse_stale_if_error(response_meta.headers()).or(previous.stale_if_error);
                    (policy, fresh_for, stale_if_error)
                }
                AfterResponse::Modified(_, _) => {
                    return Err(FetchError::new(FetchErrorKind::InvalidResource));
                }
            };
        return Ok(Arc::new(Representation {
            resource: previous.resource.clone(),
            policy,
            stored_at: now,
            fresh_for,
            fresh_until: monotonic_now + fresh_for,
            stale_if_error,
        }));
    }

    apply_default_freshness(&mut response.headers);
    let response_meta = response_from_fetch(&response)?;
    let policy = CachePolicy::new_options(
        &request,
        &response_meta,
        now,
        CacheOptions {
            cache_heuristic: 0.0,
            ..CacheOptions::default()
        },
    );
    let resource = parse_resource(key.kind, &key.url, &response.body, max_keys)?;
    let fresh_for = policy.time_to_live(now).min(MAX_FRESHNESS);
    let stale_if_error = parse_stale_if_error(response_meta.headers());
    Ok(Arc::new(Representation {
        resource,
        policy,
        stored_at: now,
        fresh_for,
        fresh_until: monotonic_now + fresh_for,
        stale_if_error,
    }))
}

pub(super) fn cache_request(key: &ResourceKey) -> Result<Request<()>, FetchError> {
    Request::builder()
        .method(http::Method::GET)
        .uri(key.url.as_str())
        .header(http::header::ACCEPT, key.kind.accept(&key.url))
        .header(http::header::ACCEPT_ENCODING, "identity")
        .body(())
        .map_err(|_| FetchError::new(FetchErrorKind::InvalidResource))
}

fn response_from_fetch(response: &FetchResponse) -> Result<Response<()>, FetchError> {
    let mut built = Response::builder().status(response.status);
    *built
        .headers_mut()
        .ok_or_else(|| FetchError::new(FetchErrorKind::InvalidResource))? =
        response.headers.clone();
    built
        .body(())
        .map_err(|_| FetchError::new(FetchErrorKind::InvalidResource))
}

pub(super) fn apply_default_freshness(headers: &mut HeaderMap) {
    let directives = headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect::<Vec<_>>();
    let no_store = directives
        .iter()
        .any(|directive| directive.eq_ignore_ascii_case("no-store"));
    let has_freshness = directives.iter().any(|directive| {
        directive
            .split_once('=')
            .filter(|(name, value)| {
                (name.trim().eq_ignore_ascii_case("max-age")
                    || name.trim().eq_ignore_ascii_case("s-maxage"))
                    && value.trim_matches('"').trim().parse::<u64>().is_ok()
            })
            .is_some()
    });
    let has_expires = headers
        .get(http::header::EXPIRES)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| httpdate::parse_http_date(value).is_ok());
    if !no_store && !has_freshness && !has_expires {
        headers.append(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("max-age=300"),
        );
    }
}

pub(super) fn parse_stale_if_error(headers: &HeaderMap) -> Option<Duration> {
    if headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("must-revalidate"))
    {
        return None;
    }
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|directive| {
            let (name, value) = directive.trim().split_once('=')?;
            name.eq_ignore_ascii_case("stale-if-error")
                .then(|| value.trim_matches('"').parse::<u64>().ok())
                .flatten()
        })
        .map(|seconds| Duration::from_secs(seconds.min(MAX_FRESHNESS.as_secs())))
}
