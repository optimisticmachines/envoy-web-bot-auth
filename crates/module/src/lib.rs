//! Envoy dynamic HTTP module for Web Bot Auth verification with Ed25519.
//!
//! Request capture and protocol parsing are kept separate from the Envoy ABI
//! adapter so the trust decisions remain testable without an Envoy process.

// Required by the factory-registration macro in the Envoy SDK.
#![allow(unpredictable_function_pointer_comparisons)]

mod cache;
mod candidate;
mod config;
mod filter;
mod policy;
mod request;
mod verify;

use config::Settings;
#[cfg(test)]
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyBuffer;
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyCounterVecId, EnvoyHistogramVecId, EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilter,
    HttpFilterConfig, declare_init_functions, envoy_log_error, envoy_log_info,
};
#[cfg(test)]
use filter::WebBotAuthFilter;
#[cfg(test)]
use policy::{Admission, InvalidKind, Reason, UnverifiedKind, VerificationResult, admission};
use request::RequestComponents;
#[cfg(test)]
use request::decode_ascii_header;
#[cfg(test)]
use request::{SignatureHeaderState, classify_signature_headers};
use std::sync::Arc;
#[cfg(test)]
use web_bot_auth::components::{CoveredComponent, DerivedComponent, HTTPFieldParameters};
#[cfg(test)]
use web_bot_auth::message_signatures::SignedMessage;

const PSEUDO_HEADER_METHOD: &str = ":method";
const PSEUDO_HEADER_AUTHORITY: &str = ":authority";
const PSEUDO_HEADER_PATH: &str = ":path";
const PSEUDO_HEADER_SCHEME: &str = ":scheme";
const HEADER_SIGNATURE: &str = "signature";
const HEADER_SIGNATURE_INPUT: &str = "signature-input";
const HEADER_SIGNATURE_AGENT: &str = "signature-agent";
const HEADER_STATUS: &str = "x-web-bot-auth-status";
const HEADER_IDENTITY: &str = "x-web-bot-auth-identity";
const HEADER_KEY_ID: &str = "x-web-bot-auth-keyid";
const METADATA_NAMESPACE: &str = "envoy.filters.http.web_bot_auth";

declare_init_functions!(program_init, new_http_filter_config);

fn program_init() -> bool {
    true
}

fn new_http_filter_config<EC, EHF>(
    envoy_config: &mut EC,
    name: &str,
    config: &[u8],
) -> Option<Box<dyn HttpFilterConfig<EHF>>>
where
    EC: EnvoyHttpFilterConfig,
    EHF: EnvoyHttpFilter,
{
    if name != "web-bot-auth" {
        return None;
    }

    let settings = match Settings::parse(config) {
        Ok(settings) => settings,
        Err(error) => {
            envoy_log_error!("invalid web-bot-auth configuration: {error}");
            return None;
        }
    };

    envoy_log_info!("web-bot-auth configuration accepted");
    let outcome_counter = match envoy_config.define_counter_vec("requests", &["outcome", "reason"])
    {
        Ok(counter) => Some(counter),
        Err(error) => {
            envoy_log_error!("web-bot-auth metric definition failed name=requests error={error:?}");
            None
        }
    };
    let duration_histogram = match envoy_config
        .define_histogram_vec("web_bot_auth_duration_us", &["phase", "result"])
    {
        Ok(histogram) => Some(histogram),
        Err(error) => {
            envoy_log_error!(
                "web-bot-auth metric definition failed name=web_bot_auth_duration_us error={error:?}"
            );
            None
        }
    };
    let cache_counter = match envoy_config.define_counter_vec("resolver_cache_events", &["event"]) {
        Ok(counter) => Some(counter),
        Err(error) => {
            envoy_log_error!(
                "web-bot-auth metric definition failed name=resolver_cache_events error={error:?}"
            );
            None
        }
    };
    let cache = settings
        .resolver
        .cache
        .as_ref()
        .map(cache::ResolutionCache::new)
        .map(Arc::new);

    Some(Box::new(WebBotAuthConfig {
        settings: Arc::new(settings),
        cache,
        outcome_counter,
        cache_counter,
        duration_histogram,
    }))
}

struct WebBotAuthConfig {
    settings: Arc<Settings>,
    cache: Option<Arc<cache::ResolutionCache>>,
    outcome_counter: Option<EnvoyCounterVecId>,
    cache_counter: Option<EnvoyCounterVecId>,
    duration_histogram: Option<EnvoyHistogramVecId>,
}

impl<EHF> HttpFilterConfig<EHF> for WebBotAuthConfig
where
    EHF: EnvoyHttpFilter,
{
    fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        filter::wrap(filter::WebBotAuthFilter::new(
            Arc::clone(&self.settings),
            self.cache.clone(),
            self.outcome_counter,
            self.cache_counter,
            self.duration_histogram,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Mode;
    use envoy_proxy_dynamic_modules_rust_sdk::MockEnvoyHttpFilter;
    use policy::VerifiedIdentity;
    use request::RequestCaptureError;
    use web_bot_auth::components::{HTTPField, HTTPFieldParametersSet};
    use web_bot_auth::{SignatureAgentLink, WebBotAuthVerifier};

    fn result_subtypes() -> Vec<VerificationResult> {
        vec![
            VerificationResult::NotPresent {
                reason: Reason::Unsigned,
            },
            VerificationResult::Invalid {
                kind: InvalidKind::Malformed,
                reason: Reason::MalformedProfile,
            },
            VerificationResult::Invalid {
                kind: InvalidKind::Rejected,
                reason: Reason::SignatureVerification,
            },
            VerificationResult::Unverified {
                kind: UnverifiedKind::Unsupported,
                reason: Reason::UnsupportedAlgorithm,
            },
            VerificationResult::Unverified {
                kind: UnverifiedKind::KeyNotFound,
                reason: Reason::KeyNotFound,
            },
            VerificationResult::Unverified {
                kind: UnverifiedKind::Unavailable,
                reason: Reason::ResolverUnavailable,
            },
            VerificationResult::Verified(VerifiedIdentity {
                identifier: "https://agent.example/keys".into(),
                key_id: "thumbprint".into(),
            }),
        ]
    }

    fn verified_result() -> VerificationResult {
        VerificationResult::Verified(VerifiedIdentity {
            identifier: "https://agent.example/keys".into(),
            key_id: "thumbprint".into(),
        })
    }

    fn assert_result_application(mode: Mode, result: VerificationResult) {
        let expected_admission = admission(mode, &result);
        let expected_status = result.status().to_owned();
        let expected_reason = result.reason().as_str().to_owned();
        let expected_identity = result.identity().cloned();
        let mut envoy = MockEnvoyHttpFilter::new();

        let metadata_status = expected_status.clone();
        let metadata_reason = expected_reason.clone();
        envoy
            .expect_set_dynamic_metadata_string_batch()
            .withf(move |namespace, entries| {
                namespace == METADATA_NAMESPACE
                    && entries
                        == [
                            ("status", metadata_status.as_str()),
                            ("reason", metadata_reason.as_str()),
                        ]
            })
            .return_const(())
            .once();
        envoy
            .expect_set_dynamic_metadata_bool()
            .withf(move |namespace, key, value| {
                namespace == METADATA_NAMESPACE
                    && key == "verified"
                    && *value == expected_identity.is_some()
            })
            .return_const(())
            .once();

        if let Some(identity) = result.identity().cloned() {
            let metadata_identity = identity.clone();
            envoy
                .expect_set_dynamic_metadata_string_batch()
                .withf(move |namespace, entries| {
                    namespace == METADATA_NAMESPACE
                        && entries
                            == [
                                ("identity", metadata_identity.identifier.as_str()),
                                ("keyid", metadata_identity.key_id.as_str()),
                            ]
                })
                .return_const(())
                .once();

            let header_identity = identity.identifier.clone();
            envoy
                .expect_set_request_header()
                .withf(move |name, value| {
                    name == HEADER_IDENTITY && value == header_identity.as_bytes()
                })
                .return_const(true)
                .once();
            let header_key_id = identity.key_id;
            envoy
                .expect_set_request_header()
                .withf(move |name, value| {
                    name == HEADER_KEY_ID && value == header_key_id.as_bytes()
                })
                .return_const(true)
                .once();
        }

        let counter_status = expected_status.clone();
        let counter_reason = expected_reason;
        envoy
            .expect_increment_counter_vec()
            .withf(move |counter, labels, amount| {
                *counter == EnvoyCounterVecId(7)
                    && labels == [counter_status.as_str(), counter_reason.as_str()]
                    && *amount == 1
            })
            .returning(|_, _, _| Ok(()))
            .once();

        let header_status = expected_status;
        envoy
            .expect_set_request_header()
            .withf(move |name, value| name == HEADER_STATUS && value == header_status.as_bytes())
            .return_const(true)
            .once();

        if let Admission::Reject { status, challenge } = expected_admission {
            envoy
                .expect_send_response()
                .withf(move |actual_status, headers, body, details| {
                    *actual_status == status
                        && headers.len() == if challenge { 2 } else { 1 }
                        && body.is_some()
                        && *details == Some("web_bot_auth_denied")
                })
                .return_const(())
                .once();
        }

        let filter = WebBotAuthFilter::new(
            Arc::new(Settings {
                mode,
                ..Settings::default()
            }),
            None,
            Some(EnvoyCounterVecId(7)),
            None,
            None,
        );
        assert_eq!(filter.apply_result(&mut envoy, &result), expected_admission);
    }

    #[test]
    fn every_result_subtype_drives_outputs_in_every_mode() {
        for result in result_subtypes() {
            assert_result_application(Mode::Observe, result);
        }
        for result in [
            VerificationResult::NotPresent {
                reason: Reason::Unsigned,
            },
            VerificationResult::Invalid {
                kind: InvalidKind::Malformed,
                reason: Reason::MalformedProfile,
            },
            VerificationResult::Unverified {
                kind: UnverifiedKind::Unavailable,
                reason: Reason::ResolverUnavailable,
            },
        ] {
            assert_result_application(Mode::Required, result);
        }
    }

    #[test]
    fn classifies_signature_header_presence() {
        let cases = [
            (false, false, false, SignatureHeaderState::Unsigned),
            (false, false, true, SignatureHeaderState::Incomplete),
            (false, true, false, SignatureHeaderState::Incomplete),
            (false, true, true, SignatureHeaderState::Incomplete),
            (true, false, false, SignatureHeaderState::Incomplete),
            (true, false, true, SignatureHeaderState::Incomplete),
            (true, true, false, SignatureHeaderState::Incomplete),
            (true, true, true, SignatureHeaderState::Candidate),
        ];

        for (has_signature, has_signature_input, has_signature_agent, expected) in cases {
            assert_eq!(
                classify_signature_headers(has_signature, has_signature_input, has_signature_agent,),
                expected,
            );
        }
    }

    #[test]
    fn removes_all_client_supplied_assertion_headers() {
        let mut envoy = MockEnvoyHttpFilter::new();
        for name in [HEADER_STATUS, HEADER_IDENTITY, HEADER_KEY_ID] {
            envoy
                .expect_remove_request_header()
                .withf(move |actual| actual == name)
                .times(1)
                .return_const(true);
        }

        filter::sanitize_assertion_headers(&mut envoy);
    }

    #[test]
    fn retrieves_raw_signature_fields() {
        let request = RequestComponents {
            signature: vec!["sig1=:first:".into(), "sig2=:second:".into()],
            signature_input: vec![r#"sig1=("@method")"#.into()],
            signature_agent: vec![
                r#"sig1="https://one.example""#.into(),
                r#"sig2="https://two.example""#.into(),
            ],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let raw_component = |name: &str| {
            CoveredComponent::HTTP(HTTPField {
                name: name.into(),
                parameters: HTTPFieldParametersSet(vec![]),
            })
        };

        assert_eq!(
            request.lookup_component(&raw_component(HEADER_SIGNATURE)),
            vec!["sig1=:first:", "sig2=:second:"],
        );
        assert_eq!(
            request.lookup_component(&raw_component(HEADER_SIGNATURE_INPUT)),
            vec![r#"sig1=("@method")"#],
        );
        assert_eq!(
            request.lookup_component(&raw_component(HEADER_SIGNATURE_AGENT)),
            vec![
                r#"sig1="https://one.example""#,
                r#"sig2="https://two.example""#,
            ],
        );
    }

    #[test]
    fn retrieves_a_selected_signature_agent_dictionary_member() {
        let request = RequestComponents {
            signature_agent: vec![
                r#"sig1="https://one.example", sig2="https://two.example""#.into(),
            ],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let component = CoveredComponent::HTTP(HTTPField {
            name: HEADER_SIGNATURE_AGENT.into(),
            parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Key("sig1".into())]),
        });

        assert_eq!(
            request.lookup_component(&component),
            vec![r#""https://one.example""#],
        );
    }

    #[test]
    fn returns_empty_when_signature_agent_key_is_missing() {
        let request = RequestComponents {
            signature_agent: vec![r#"sig1="https://one.example""#.into()],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let component = CoveredComponent::HTTP(HTTPField {
            name: HEADER_SIGNATURE_AGENT.into(),
            parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Key("sig2".into())]),
        });

        assert_eq!(request.lookup_component(&component), Vec::<String>::new(),);
    }

    #[test]
    fn returns_empty_when_signature_agent_dictionary_is_malformed() {
        let request = RequestComponents {
            signature_agent: vec![r#"sig1="https://one.example", broken="#.into()],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let component = CoveredComponent::HTTP(HTTPField {
            name: HEADER_SIGNATURE_AGENT.into(),
            parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Key("sig1".into())]),
        });

        assert_eq!(request.lookup_component(&component), Vec::<String>::new(),);
    }

    #[test]
    fn returns_empty_for_unsupported_signature_agent_parameters() {
        let request = RequestComponents {
            signature_agent: vec![r#"sig1="https://one.example""#.into()],
            ..RequestComponents::from_pseudo_headers("GET", "example.test", "/")
        };

        let component = CoveredComponent::HTTP(HTTPField {
            name: HEADER_SIGNATURE_AGENT.into(),
            parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Sf]),
        });

        assert_eq!(request.lookup_component(&component), Vec::<String>::new(),);
    }

    #[test]
    fn decodes_an_ascii_pseudo_header() {
        let buffer = EnvoyBuffer::new(b"/caf%C3%A9");

        assert_eq!(
            decode_ascii_header(&buffer, PSEUDO_HEADER_PATH),
            Ok("/caf%C3%A9"),
        );
    }

    #[test]
    fn rejects_a_non_ascii_pseudo_header() {
        let buffer = EnvoyBuffer::new("/café".as_bytes());

        assert_eq!(
            decode_ascii_header(&buffer, PSEUDO_HEADER_PATH),
            Err(RequestCaptureError::NonAsciiHeader(PSEUDO_HEADER_PATH,)),
        );
    }

    #[test]
    fn rejects_invalid_utf8_in_a_pseudo_header() {
        let buffer = EnvoyBuffer::new(b"/caf\xff");

        assert_eq!(
            decode_ascii_header(&buffer, PSEUDO_HEADER_PATH),
            Err(RequestCaptureError::InvalidUtf8(PSEUDO_HEADER_PATH)),
        );
    }

    #[test]
    fn lookup_returns_empty_for_unsupported_components() {
        let request =
            RequestComponents::from_pseudo_headers("GET", "example.test:8443", "/ask?q=bears");

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(
                DerivedComponent::RequestTarget { req: false },
            )),
            Vec::<String>::new(),
        );

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Method {
                req: true
            },)),
            Vec::<String>::new(),
        );
    }

    #[test]
    fn reconstructs_method_authority_path_and_query() {
        let request =
            RequestComponents::from_pseudo_headers("get", " example.test:8443 ", "/ask?q=bears");

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Method {
                req: false
            })),
            vec!["get"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Authority {
                req: false
            })),
            vec!["example.test:8443"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Path {
                req: false
            })),
            vec!["/ask"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Query {
                req: false
            })),
            vec!["?q=bears"]
        );
    }

    #[test]
    fn reconstructs_an_absent_query_as_an_empty_component() {
        let request = RequestComponents::from_pseudo_headers("GET", "example.test", "/health");

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Path {
                req: false
            })),
            vec!["/health"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Query {
                req: false
            })),
            vec![""]
        );
    }

    #[test]
    fn reconstructs_an_empty_query_with_its_delimiter() {
        let request = RequestComponents::from_pseudo_headers("GET", "example.test", "/health?");

        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Path {
                req: false
            })),
            vec!["/health"]
        );
        assert_eq!(
            request.lookup_component(&CoveredComponent::Derived(DerivedComponent::Query {
                req: false
            })),
            vec!["?"]
        );
    }

    #[test]
    fn parses_a_web_bot_auth_candidate() {
        let request = RequestComponents {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "example.test".into(),
            path: "/robots.txt".into(),
            query: "".into(),
            signature: vec!["sig1=:AA==:".into()],
            signature_input: vec![r#"sig1=("@method" "@authority" "@path" "signature-agent";key="sig1");created=1735689600;expires=1735693200;keyid="test-key";alg="ed25519";tag="web-bot-auth""#.into()],
            signature_agent: vec![r#"sig1="https://agent.example/.well-known/http-message-signatures-directory""#.into()],
        };

        let verifier = WebBotAuthVerifier::parse(&request).expect("candidate should parse");

        assert_eq!(verifier.get_parsed_label().label.as_str(), "sig1");
        assert_eq!(
            verifier.get_signature_agents(),
            &[SignatureAgentLink::External(
                "https://agent.example/.well-known/http-message-signatures-directory".into(),
            )],
        );
    }

    #[test]
    fn does_not_forward_identity_headers_when_disabled() {
        let mut envoy = MockEnvoyHttpFilter::new();
        envoy
            .expect_set_dynamic_metadata_string_batch()
            .withf(|namespace, entries| {
                namespace == METADATA_NAMESPACE
                    && entries == [("status", "verified"), ("reason", "verified")]
            })
            .return_const(())
            .once();
        envoy
            .expect_set_dynamic_metadata_bool()
            .withf(|namespace, key, value| {
                namespace == METADATA_NAMESPACE && key == "verified" && *value
            })
            .return_const(())
            .once();
        envoy
            .expect_set_dynamic_metadata_string_batch()
            .withf(|namespace, entries| {
                namespace == METADATA_NAMESPACE
                    && entries
                        == [
                            ("identity", "https://agent.example/keys"),
                            ("keyid", "thumbprint"),
                        ]
            })
            .return_const(())
            .once();
        envoy
            .expect_increment_counter_vec()
            .withf(|counter, labels, amount| {
                *counter == EnvoyCounterVecId(7)
                    && labels == ["verified", "verified"]
                    && *amount == 1
            })
            .returning(|_, _, _| Ok(()))
            .once();

        let filter = WebBotAuthFilter::new(
            Arc::new(Settings {
                forward_identity_headers: false,
                ..Settings::default()
            }),
            None,
            Some(EnvoyCounterVecId(7)),
            None,
            None,
        );
        assert_eq!(
            filter.apply_result(&mut envoy, &verified_result()),
            Admission::Allow
        );
    }
}
