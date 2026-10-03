//! Envoy request state and callback pipeline.

use crate::cache::{ResolutionCache, ResolutionCacheKey, cache_valid_for};
use crate::candidate::VerificationCandidate;
use crate::config::Settings;
use crate::policy::{
    Admission, InvalidKind, Reason, UnverifiedKind, VerificationResult, admission,
};
use crate::request::{RequestComponents, SignatureHeaderState, classify_signature_headers};
use crate::verify::{join_response_body, response_status, verify_resolver_response};
use envoy_proxy_dynamic_modules_rust_sdk::{
    CatchUnwind, EnvoyBuffer, EnvoyCounterVecId, EnvoyHistogramVecId, EnvoyHttpFilter, HttpFilter,
    abi, envoy_log_error,
};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use web_bot_auth_protocol::{
    MAX_RESOLVE_BODY_BYTES, ResolveRequest, ResolveResponse, ResolverApiVersion,
};

pub(crate) struct WebBotAuthFilter {
    settings: Arc<Settings>,
    cache: Option<Arc<ResolutionCache>>,
    pending: Option<PendingVerification>,
    outcome_counter: Option<EnvoyCounterVecId>,
    cache_counter: Option<EnvoyCounterVecId>,
    duration_histogram: Option<EnvoyHistogramVecId>,
}

impl WebBotAuthFilter {
    pub(crate) fn new(
        settings: Arc<Settings>,
        cache: Option<Arc<ResolutionCache>>,
        outcome_counter: Option<EnvoyCounterVecId>,
        cache_counter: Option<EnvoyCounterVecId>,
        duration_histogram: Option<EnvoyHistogramVecId>,
    ) -> Self {
        Self {
            settings,
            cache,
            pending: None,
            outcome_counter,
            cache_counter,
            duration_histogram,
        }
    }

    fn finish<EHF: EnvoyHttpFilter>(
        &self,
        envoy_filter: &mut EHF,
        result: VerificationResult,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_headers_status {
        match self.apply_result(envoy_filter, &result) {
            Admission::Allow => {
                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
            }
            Admission::Reject { .. } => {
                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration
            }
        }
    }

    pub(crate) fn apply_result<EHF: EnvoyHttpFilter>(
        &self,
        envoy_filter: &mut EHF,
        result: &VerificationResult,
    ) -> Admission {
        let status = result.status();
        let reason = result.reason().as_str();
        envoy_filter.set_dynamic_metadata_string_batch(
            crate::METADATA_NAMESPACE,
            &[("status", status), ("reason", reason)],
        );
        if let Some(counter) = self.outcome_counter {
            let _ = envoy_filter.increment_counter_vec(counter, &[status, reason], 1);
        }
        envoy_filter.set_dynamic_metadata_bool(
            crate::METADATA_NAMESPACE,
            "verified",
            matches!(result, VerificationResult::Verified(_)),
        );
        if let Some(identity) = result.identity() {
            envoy_filter.set_dynamic_metadata_string_batch(
                crate::METADATA_NAMESPACE,
                &[
                    ("identity", &identity.identifier),
                    ("keyid", &identity.key_id),
                ],
            );
        }

        if self.settings.forward_identity_headers {
            envoy_filter.set_request_header(crate::HEADER_STATUS, status.as_bytes());
            if let Some(identity) = result.identity() {
                envoy_filter
                    .set_request_header(crate::HEADER_IDENTITY, identity.identifier.as_bytes());
                envoy_filter.set_request_header(crate::HEADER_KEY_ID, identity.key_id.as_bytes());
            }
        }

        let decision = admission(self.settings.mode, result);
        if let Admission::Reject { status, challenge } = decision {
            let challenge_headers: [(&str, &[u8]); 2] = [
                ("content-type", b"text/plain; charset=utf-8"),
                ("accept-signature", b"sig=(\"@method\" \"@authority\" \"@path\" \"signature-agent\";key=\"sig\");alg=\"ed25519\";tag=\"web-bot-auth\""),
            ];
            let plain_headers: [(&str, &[u8]); 1] =
                [("content-type", b"text/plain; charset=utf-8")];
            let headers = if challenge {
                &challenge_headers[..]
            } else {
                &plain_headers[..]
            };
            let body = match status {
                400 => b"malformed Web Bot Auth request\n".as_slice(),
                503 => b"Web Bot Auth verification unavailable\n".as_slice(),
                _ => b"Web Bot Auth required or invalid\n".as_slice(),
            };
            envoy_filter.send_response(status, headers, Some(body), Some("web_bot_auth_denied"));
        }
        decision
    }
}

struct PendingVerification {
    callout_id: u64,
    candidate: VerificationCandidate,
    cache_key: Option<ResolutionCacheKey>,
    callout_started_at: Instant,
}

fn record_duration<EHF: EnvoyHttpFilter>(
    envoy_filter: &mut EHF,
    histogram: Option<EnvoyHistogramVecId>,
    phase: &'static str,
    result: &'static str,
    started_at: Instant,
) {
    if let Some(histogram) = histogram {
        let elapsed_us = u64::try_from(started_at.elapsed().as_micros()).unwrap_or(u64::MAX);
        let _ = envoy_filter.record_histogram_value_vec(histogram, &[phase, result], elapsed_us);
    }
}

fn record_cache_event<EHF: EnvoyHttpFilter>(
    envoy_filter: &mut EHF,
    counter: Option<EnvoyCounterVecId>,
    event: &'static str,
) {
    if let Some(counter) = counter {
        let _ = envoy_filter.increment_counter_vec(counter, &[event], 1);
    }
}

impl<EHF> HttpFilter<EHF> for WebBotAuthFilter
where
    EHF: EnvoyHttpFilter,
{
    fn on_request_headers(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_headers_status {
        sanitize_assertion_headers(envoy_filter);

        let has_signature = envoy_filter
            .get_request_header_value(crate::HEADER_SIGNATURE)
            .is_some();
        let has_signature_input = envoy_filter
            .get_request_header_value(crate::HEADER_SIGNATURE_INPUT)
            .is_some();
        let has_signature_agent = envoy_filter
            .get_request_header_value(crate::HEADER_SIGNATURE_AGENT)
            .is_some();

        match classify_signature_headers(has_signature, has_signature_input, has_signature_agent) {
            SignatureHeaderState::Unsigned => self.finish(
                envoy_filter,
                VerificationResult::NotPresent {
                    reason: Reason::Unsigned,
                },
            ),
            SignatureHeaderState::Incomplete => self.finish(
                envoy_filter,
                VerificationResult::Invalid {
                    kind: InvalidKind::Malformed,
                    reason: Reason::IncompleteFields,
                },
            ),
            SignatureHeaderState::Candidate => {
                if !end_of_stream {
                    return self.finish(
                        envoy_filter,
                        VerificationResult::Unverified {
                            kind: UnverifiedKind::Unsupported,
                            reason: Reason::RequestBodyUnsupported,
                        },
                    );
                }
                let capture_started_at = Instant::now();
                let request = match RequestComponents::try_from_envoy(envoy_filter) {
                    Ok(request) => {
                        record_duration(
                            envoy_filter,
                            self.duration_histogram,
                            "candidate_capture",
                            "success",
                            capture_started_at,
                        );
                        request
                    }
                    Err(_) => {
                        record_duration(
                            envoy_filter,
                            self.duration_histogram,
                            "candidate_capture",
                            "error",
                            capture_started_at,
                        );
                        return self.finish(
                            envoy_filter,
                            VerificationResult::Invalid {
                                kind: InvalidKind::Malformed,
                                reason: Reason::RequestCapture,
                            },
                        );
                    }
                };
                let parse_started_at = Instant::now();
                let candidate = match VerificationCandidate::parse(
                    &request,
                    self.settings.accept_legacy_signature_agent,
                    &self.settings.required_components,
                    unix_time(),
                    self.settings.max_signature_lifetime_seconds,
                    self.settings.clock_skew_seconds,
                ) {
                    Ok(candidate) => {
                        record_duration(
                            envoy_filter,
                            self.duration_histogram,
                            "candidate_parse",
                            "success",
                            parse_started_at,
                        );
                        candidate
                    }
                    Err(error) => {
                        record_duration(
                            envoy_filter,
                            self.duration_histogram,
                            "candidate_parse",
                            "error",
                            parse_started_at,
                        );
                        return self.finish(envoy_filter, error.result());
                    }
                };
                let cache_key = self
                    .cache
                    .as_ref()
                    .and_then(|_| ResolutionCacheKey::from_candidate(&candidate));
                if let (Some(cache), Some(key)) = (&self.cache, &cache_key) {
                    let lookup_started_at = Instant::now();
                    if let Some(response) = cache.get(key) {
                        record_cache_event(envoy_filter, self.cache_counter, "hit");
                        record_duration(
                            envoy_filter,
                            self.duration_histogram,
                            "resolver_cache_lookup",
                            "hit",
                            lookup_started_at,
                        );
                        let verify_started_at = Instant::now();
                        let result = verify_resolver_response(candidate, Ok((*response).clone()));
                        record_duration(
                            envoy_filter,
                            self.duration_histogram,
                            "response_verify",
                            result.status(),
                            verify_started_at,
                        );
                        return self.finish(envoy_filter, result);
                    }
                    record_cache_event(envoy_filter, self.cache_counter, "miss");
                    record_duration(
                        envoy_filter,
                        self.duration_histogram,
                        "resolver_cache_lookup",
                        "miss",
                        lookup_started_at,
                    );
                }
                let send_setup_started_at = Instant::now();
                let resolver_request = ResolveRequest {
                    api_version: ResolverApiVersion::V1,
                    discovery: candidate.discovery,
                    agent_url: candidate.signed_url.clone(),
                    key_id: candidate.key_id.clone(),
                };
                let body = match serde_json::to_vec(&resolver_request) {
                    Ok(body) => body,
                    Err(_) => {
                        record_duration(
                            envoy_filter,
                            self.duration_histogram,
                            "resolver_send",
                            "error",
                            send_setup_started_at,
                        );
                        return self.finish(
                            envoy_filter,
                            VerificationResult::Unverified {
                                kind: UnverifiedKind::Unavailable,
                                reason: Reason::ResolverEncoding,
                            },
                        );
                    }
                };
                if body.len() > MAX_RESOLVE_BODY_BYTES {
                    record_duration(
                        envoy_filter,
                        self.duration_histogram,
                        "resolver_send",
                        "error",
                        send_setup_started_at,
                    );
                    return self.finish(
                        envoy_filter,
                        VerificationResult::Invalid {
                            kind: InvalidKind::Malformed,
                            reason: Reason::ProfileFieldTooLarge,
                        },
                    );
                }
                let headers: [(&str, &[u8]); 5] = [
                    (":method", b"POST"),
                    (":path", b"/v1/resolve"),
                    ("host", b"web-bot-auth-resolver"),
                    ("content-type", b"application/json"),
                    ("accept", b"application/json"),
                ];
                // Start before initiating the callout so wall time covers the resolver operation
                // as observed by the filter, through its completion callback.
                let callout_started_at = Instant::now();
                let (result, callout_id) = envoy_filter.send_http_callout(
                    &self.settings.resolver.cluster,
                    &headers,
                    Some(&body),
                    self.settings.resolver.timeout_ms,
                );
                if !matches!(
                    result,
                    abi::envoy_dynamic_module_type_http_callout_init_result::Success
                ) {
                    record_duration(
                        envoy_filter,
                        self.duration_histogram,
                        "resolver_send",
                        "error",
                        send_setup_started_at,
                    );
                    record_duration(
                        envoy_filter,
                        self.duration_histogram,
                        "resolver_callout",
                        "error",
                        callout_started_at,
                    );
                    return self.finish(
                        envoy_filter,
                        VerificationResult::Unverified {
                            kind: UnverifiedKind::Unavailable,
                            reason: Reason::ResolverUnavailable,
                        },
                    );
                }
                record_duration(
                    envoy_filter,
                    self.duration_histogram,
                    "resolver_send",
                    "success",
                    send_setup_started_at,
                );
                self.pending = Some(PendingVerification {
                    callout_id,
                    candidate,
                    cache_key,
                    callout_started_at,
                });
                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopAllIterationAndWatermark
            }
        }
    }

    fn on_http_callout_done(
        &mut self,
        envoy_filter: &mut EHF,
        callout_id: u64,
        result: abi::envoy_dynamic_module_type_http_callout_result,
        response_headers: Option<&[(EnvoyBuffer, EnvoyBuffer)]>,
        response_body: Option<&[EnvoyBuffer]>,
    ) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if pending.callout_id != callout_id {
            record_duration(
                envoy_filter,
                self.duration_histogram,
                "resolver_callout",
                "error",
                pending.callout_started_at,
            );
            envoy_log_error!("web-bot-auth reason=resolver_callout_mismatch");
            let result = VerificationResult::Unverified {
                kind: UnverifiedKind::Unavailable,
                reason: Reason::ResolverCalloutMismatch,
            };
            if matches!(self.apply_result(envoy_filter, &result), Admission::Allow) {
                envoy_filter.continue_decoding();
            }
            return;
        }
        let resolver_response = if !matches!(
            result,
            abi::envoy_dynamic_module_type_http_callout_result::Success
        ) || response_status(response_headers) != Some(200)
        {
            Err(Reason::ResolverUnavailable)
        } else {
            response_body
                .and_then(join_response_body)
                .and_then(|body| serde_json::from_slice::<ResolveResponse>(&body).ok())
                .ok_or(Reason::ResolverResponse)
        };
        let response_to_cache = if self.cache.is_some() && pending.cache_key.is_some() {
            match resolver_response.as_ref() {
                Ok(response @ ResolveResponse::Resolved { .. }) => {
                    cache_valid_for(response_headers).map(|valid_for| (response.clone(), valid_for))
                }
                _ => None,
            }
        } else {
            None
        };

        record_duration(
            envoy_filter,
            self.duration_histogram,
            "resolver_callout",
            if resolver_response.is_ok() {
                "success"
            } else {
                "error"
            },
            pending.callout_started_at,
        );
        let verify_started_at = Instant::now();
        let result = verify_resolver_response(pending.candidate, resolver_response);
        record_duration(
            envoy_filter,
            self.duration_histogram,
            "response_verify",
            result.status(),
            verify_started_at,
        );
        if matches!(result, VerificationResult::Verified(_))
            && let (Some(cache), Some(key)) = (&self.cache, pending.cache_key)
        {
            let inserted = response_to_cache.is_some_and(|(response, valid_for)| {
                cache.insert(key, response, pending.callout_started_at, valid_for)
            });
            record_cache_event(
                envoy_filter,
                self.cache_counter,
                if inserted { "insert" } else { "not_cacheable" },
            );
        }
        match self.apply_result(envoy_filter, &result) {
            Admission::Allow => envoy_filter.continue_decoding(),
            Admission::Reject { .. } => {}
        }
    }
}

pub(crate) fn sanitize_assertion_headers(envoy_filter: &mut impl EnvoyHttpFilter) {
    for header in [
        crate::HEADER_STATUS,
        crate::HEADER_IDENTITY,
        crate::HEADER_KEY_ID,
    ] {
        envoy_filter.remove_request_header(header);
    }
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

pub(crate) fn wrap<EHF>(filter: WebBotAuthFilter) -> Box<dyn HttpFilter<EHF>>
where
    EHF: EnvoyHttpFilter,
{
    Box::new(CatchUnwind::new(filter))
}
