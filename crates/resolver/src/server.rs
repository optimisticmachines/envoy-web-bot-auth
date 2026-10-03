//! HTTP boundary for the resolver service.
//!
//! The router is kept in the library so tests can exercise the real body,
//! JSON, and response mapping rules without starting a process.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use web_bot_auth_protocol::{CACHE_VALID_FOR_HEADER, ResolveRequest};

use crate::{FetchErrorKind, Resolution, ResolverService};

#[derive(Clone)]
struct AppState {
    resolver: ResolverService,
}

pub fn router(resolver: ResolverService) -> Router {
    Router::new()
        .route("/v1/resolve", post(resolve))
        .route("/healthz", get(health))
        .layer(DefaultBodyLimit::max(resolver.inbound_body_limit()))
        .with_state(AppState { resolver })
}

async fn resolve(
    State(state): State<AppState>,
    Json(request): Json<ResolveRequest>,
) -> impl IntoResponse {
    match state.resolver.resolve_with_metadata(request).await {
        Ok(resolution) => resolution_response(resolution),
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

pub fn resolution_response(resolution: Resolution) -> Response {
    let mut response = (StatusCode::OK, Json(resolution.response)).into_response();
    let milliseconds = u64::try_from(resolution.cache_valid_for.as_millis()).unwrap_or(u64::MAX);
    if let Ok(value) = HeaderValue::from_str(&milliseconds.to_string()) {
        response.headers_mut().insert(CACHE_VALID_FOR_HEADER, value);
    }
    response
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}
