use serde::Deserialize;
use std::error::Error;
use std::fmt;

const DEFAULT_CLUSTER: &str = "web-bot-auth-key-resolver";
const DEFAULT_TIMEOUT_MS: u64 = 2_000;
// Keep this at Envoy's outer callout ceiling.
const MAX_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_MAX_LIFETIME_SECONDS: u64 = 86_400;
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 5;
const DEFAULT_CACHE_ENTRIES: u64 = 1_024;
const MAX_CACHE_ENTRIES: u64 = 4_096;
const DEFAULT_CACHE_TTL_MS: u64 = 5_000;
const MAX_CACHE_TTL_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    /// Allows every request while recording its authentication outcome.
    #[default]
    Observe,
    /// Allows requests without authentication, but requires presented authentication to verify.
    Optional,
    /// Allows only verified authentication. Rejects missing, invalid, or inconclusive results.
    Required,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolverSettings {
    #[serde(default = "default_cluster")]
    pub(crate) cluster: String,
    #[serde(default = "default_timeout_ms")]
    pub(crate) timeout_ms: u64,
    #[serde(default)]
    pub(crate) cache: Option<ResolverCacheSettings>,
}

impl Default for ResolverSettings {
    fn default() -> Self {
        Self {
            cluster: default_cluster(),
            timeout_ms: default_timeout_ms(),
            cache: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ResolverCacheSettings {
    pub(crate) max_entries: u64,
    pub(crate) max_ttl_ms: u64,
}

impl Default for ResolverCacheSettings {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_CACHE_ENTRIES,
            max_ttl_ms: DEFAULT_CACHE_TTL_MS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Settings {
    pub(crate) mode: Mode,
    pub(crate) resolver: ResolverSettings,
    pub(crate) max_signature_lifetime_seconds: u64,
    pub(crate) clock_skew_seconds: u64,
    pub(crate) required_components: Vec<String>,
    pub(crate) accept_legacy_signature_agent: bool,
    pub(crate) forward_identity_headers: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            resolver: ResolverSettings::default(),
            max_signature_lifetime_seconds: DEFAULT_MAX_LIFETIME_SECONDS,
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
            required_components: Vec::new(),
            accept_legacy_signature_agent: false,
            forward_identity_headers: true,
        }
    }
}

#[derive(Debug)]
pub(crate) enum ConfigError {
    Json(serde_json::Error),
    EmptyResolverCluster,
    ZeroResolverTimeout,
    ResolverTimeoutTooLarge,
    InvalidResolverCacheEntries,
    InvalidResolverCacheTtl,
    ZeroSignatureLifetime,
    InvalidRequiredComponent(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "{error}"),
            Self::EmptyResolverCluster => write!(formatter, "resolver.cluster must not be empty"),
            Self::ZeroResolverTimeout => write!(formatter, "resolver.timeout_ms must be positive"),
            Self::ResolverTimeoutTooLarge => write!(
                formatter,
                "resolver.timeout_ms must not exceed {MAX_TIMEOUT_MS} milliseconds"
            ),
            Self::InvalidResolverCacheEntries => write!(
                formatter,
                "resolver.cache.max_entries must be between 1 and {MAX_CACHE_ENTRIES}"
            ),
            Self::InvalidResolverCacheTtl => write!(
                formatter,
                "resolver.cache.max_ttl_ms must be between 1 and {MAX_CACHE_TTL_MS}"
            ),
            Self::ZeroSignatureLifetime => {
                write!(formatter, "max_signature_lifetime_seconds must be positive")
            }
            Self::InvalidRequiredComponent(component) => write!(
                formatter,
                "required component {component:?} is not resolved by the request adapter"
            ),
        }
    }
}

impl Error for ConfigError {}

impl Settings {
    pub(crate) fn parse(config: &[u8]) -> Result<Self, ConfigError> {
        let settings = if config.is_empty() {
            Self::default()
        } else {
            serde_json::from_slice(config).map_err(ConfigError::Json)?
        };
        if settings.resolver.cluster.is_empty() {
            return Err(ConfigError::EmptyResolverCluster);
        }
        if settings.resolver.timeout_ms == 0 {
            return Err(ConfigError::ZeroResolverTimeout);
        }
        if settings.resolver.timeout_ms > MAX_TIMEOUT_MS {
            return Err(ConfigError::ResolverTimeoutTooLarge);
        }
        if let Some(cache) = &settings.resolver.cache {
            if !(1..=MAX_CACHE_ENTRIES).contains(&cache.max_entries) {
                return Err(ConfigError::InvalidResolverCacheEntries);
            }
            if !(1..=MAX_CACHE_TTL_MS).contains(&cache.max_ttl_ms) {
                return Err(ConfigError::InvalidResolverCacheTtl);
            }
        }
        if settings.max_signature_lifetime_seconds == 0 {
            return Err(ConfigError::ZeroSignatureLifetime);
        }
        for component in &settings.required_components {
            if !valid_component_name(component) {
                return Err(ConfigError::InvalidRequiredComponent(component.clone()));
            }
        }
        Ok(settings)
    }
}

fn valid_component_name(component: &str) -> bool {
    matches!(
        component,
        "@method"
            | "@authority"
            | "@scheme"
            | "@target-uri"
            | "@path"
            | "@query"
            | "signature"
            | "signature-input"
            | "signature-agent"
    )
}

fn default_cluster() -> String {
    DEFAULT_CLUSTER.to_owned()
}
const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_object_uses_public_defaults() {
        let settings = Settings::parse(b"{}").expect("defaults should parse");
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn parses_the_documented_configuration() {
        let settings = Settings::parse(
            br#"{
            "mode":"required",
            "resolver":{"cluster":"resolver", "timeout_ms":1500},
            "max_signature_lifetime_seconds":300,
            "clock_skew_seconds":10,
            "required_components":["@method", "@path"],
            "accept_legacy_signature_agent":true,
            "forward_identity_headers":false
        }"#,
        )
        .expect("valid settings should parse");
        assert_eq!(settings.mode, Mode::Required);
        assert_eq!(settings.resolver.cluster, "resolver");
        assert_eq!(settings.required_components, ["@method", "@path"]);
        assert!(!settings.forward_identity_headers);
        assert!(settings.resolver.cache.is_none());
    }

    #[test]
    fn cache_is_opt_in_and_bounded() {
        let settings =
            Settings::parse(br#"{"resolver":{"cache":{}}}"#).expect("cache defaults should parse");
        assert_eq!(
            settings.resolver.cache,
            Some(ResolverCacheSettings::default())
        );
        assert!(matches!(
            Settings::parse(br#"{"resolver":{"cache":{"max_entries":0}}}"#),
            Err(ConfigError::InvalidResolverCacheEntries)
        ));
        assert!(matches!(
            Settings::parse(br#"{"resolver":{"cache":{"max_ttl_ms":60001}}}"#),
            Err(ConfigError::InvalidResolverCacheTtl)
        ));
    }

    #[test]
    fn rejects_unknown_fields_and_invalid_bounds() {
        assert!(matches!(
            Settings::parse(br#"{"response_header_value":"old"}"#),
            Err(ConfigError::Json(_))
        ));
        assert!(matches!(
            Settings::parse(br#"{"resolver":{"timeout_ms":0}}"#),
            Err(ConfigError::ZeroResolverTimeout)
        ));
        assert!(matches!(
            Settings::parse(br#"{"resolver":{"timeout_ms":2001}}"#),
            Err(ConfigError::ResolverTimeoutTooLarge)
        ));
        assert!(matches!(
            Settings::parse(br#"{"required_components":["content-digest"]}"#),
            Err(ConfigError::InvalidRequiredComponent(_))
        ));
    }
}
