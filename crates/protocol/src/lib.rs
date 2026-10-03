//! Versioned wire types and discovery URL rules shared by the module and resolver.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};
use url::Url;

pub const MAX_AGENT_URL_BYTES: usize = 2_048;
pub const MAX_KEY_ID_BYTES: usize = 512;
pub const MAX_RESOLVE_BODY_BYTES: usize = 8 * 1_024;
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
/// Resolver response header carrying conservative remaining cache freshness.
pub const CACHE_VALID_FOR_HEADER: &str = "x-web-bot-auth-cache-valid-for-ms";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum ResolverApiVersion {
    /// First version of the module-to-resolver JSON contract.
    #[serde(rename = "v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMechanism {
    Directory,
    JwksUri,
    Cimd,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub api_version: ResolverApiVersion,
    pub discovery: DiscoveryMechanism,
    pub agent_url: String,
    pub key_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519Jwk {
    kty: OkpKeyType,
    crv: Ed25519Curve,
    pub x: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
enum OkpKeyType {
    #[serde(rename = "OKP")]
    Okp,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
enum Ed25519Curve {
    Ed25519,
}

impl Ed25519Jwk {
    pub fn new(x: String) -> Self {
        Self {
            kty: OkpKeyType::Okp,
            crv: Ed25519Curve::Ed25519,
            x,
        }
    }

    /// Computes the RFC 7638 thumbprint without depending on a verifier crate.
    pub fn b64_thumbprint(&self) -> String {
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, self.x);
        let digest = Sha256::digest(canonical.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }

    pub fn is_valid_public_key(&self) -> bool {
        URL_SAFE_NO_PAD
            .decode(&self.x)
            .is_ok_and(|bytes| bytes.len() == 32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryTarget {
    pub fetch_url: Url,
    pub normalized_identifier: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryUrlError {
    TooLong,
    InvalidUrl,
    InvalidScheme,
    MissingHost,
    UserInfo,
    DirectoryNotOrigin,
}

impl fmt::Display for DiscoveryUrlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLong => "agent URL exceeds 2048 bytes",
            Self::InvalidUrl => "agent URL is not a valid URL",
            Self::InvalidScheme => "agent URL must use HTTPS",
            Self::MissingHost => "agent URL must contain a host",
            Self::UserInfo => "agent URL must not contain user information",
            Self::DirectoryNotOrigin => {
                "directory discovery must be an origin without query or fragment"
            }
        })
    }
}

impl Error for DiscoveryUrlError {}

pub fn parse_discovery_target(
    value: &str,
    discovery: DiscoveryMechanism,
) -> Result<DiscoveryTarget, DiscoveryUrlError> {
    if value.len() > MAX_AGENT_URL_BYTES {
        return Err(DiscoveryUrlError::TooLong);
    }
    let mut url = Url::parse(value).map_err(|_| DiscoveryUrlError::InvalidUrl)?;
    if url.scheme() != "https" {
        return Err(DiscoveryUrlError::InvalidScheme);
    }
    if url.host_str().is_none() {
        return Err(DiscoveryUrlError::MissingHost);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DiscoveryUrlError::UserInfo);
    }
    if matches!(discovery, DiscoveryMechanism::Directory) {
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err(DiscoveryUrlError::DirectoryNotOrigin);
        }
        url.set_path(DIRECTORY_PATH);
    }
    url.set_fragment(None);
    let mut normalized = url.clone();
    normalized.set_query(None);
    normalized.set_fragment(None);
    let normalized_path = normalize_path(normalized.path());
    normalized.set_path(&normalized_path);
    Ok(DiscoveryTarget {
        fetch_url: url,
        normalized_identifier: normalized.to_string(),
    })
}

fn normalize_path(path: &str) -> String {
    remove_dot_segments(&normalize_percent_encoding(path))
}

fn normalize_percent_encoding(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut normalized = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            let byte = (high << 4) | low;
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                normalized.push(byte as char);
            } else {
                normalized.push('%');
                normalized.push(hex_digit(high));
                normalized.push(hex_digit(low));
            }
            index += 3;
            continue;
        }
        normalized.push(bytes[index] as char);
        index += 1;
    }
    normalized
}

fn remove_dot_segments(path: &str) -> String {
    let mut input = path.to_owned();
    let mut output = String::new();

    while !input.is_empty() {
        if input == "." || input == ".." {
            input.clear();
        } else if let Some(rest) = input.strip_prefix("../") {
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("./") {
            input = rest.to_owned();
        } else if input == "/." {
            input.replace_range(..2, "/");
        } else if let Some(rest) = input.strip_prefix("/./") {
            input = format!("/{rest}");
        } else if input == "/.." {
            input.replace_range(..3, "/");
            remove_last_path_segment(&mut output);
        } else if let Some(rest) = input.strip_prefix("/../") {
            input = format!("/{rest}");
            remove_last_path_segment(&mut output);
        } else {
            let segment_end = input[1..].find('/').map_or(input.len(), |index| index + 1);
            output.push_str(&input[..segment_end]);
            input.drain(..segment_end);
        }
    }

    output
}

fn remove_last_path_segment(output: &mut String) {
    if let Some(separator) = output.rfind('/') {
        output.truncate(separator);
    } else {
        output.clear();
    }
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'A' + value - 10) as char,
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolveResponse {
    Resolved {
        normalized_identifier: String,
        jwk: Ed25519Jwk,
    },
    KeyNotFound {
        normalized_identifier: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

    #[test]
    fn request_wire_format_is_exact() {
        let request = ResolveRequest {
            api_version: ResolverApiVersion::V1,
            discovery: DiscoveryMechanism::JwksUri,
            agent_url: "https://agent.example/keys?generation=2".into(),
            key_id: "thumbprint".into(),
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            include_str!("../tests/wire/resolve-request.json").trim(),
        );
    }

    #[test]
    fn unknown_resolver_api_version_is_rejected() {
        let request =
            include_str!("../tests/wire/resolve-request.json").replace("\"v1\"", "\"v2\"");
        assert!(serde_json::from_str::<ResolveRequest>(&request).is_err());
    }

    #[test]
    fn resolved_response_wire_format_is_exact() {
        let response = ResolveResponse::Resolved {
            normalized_identifier: "https://agent.example/keys".into(),
            jwk: Ed25519Jwk::new(X.into()),
        };
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            include_str!("../tests/wire/resolve-resolved.json")
                .trim()
                .replace("TEST_X", X),
        );
    }

    #[test]
    fn key_not_found_response_wire_format_is_exact() {
        let response = ResolveResponse::KeyNotFound {
            normalized_identifier: "https://agent.example/keys".into(),
        };
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            include_str!("../tests/wire/resolve-key-not-found.json").trim(),
        );
    }

    #[test]
    fn discovery_queries_are_fetch_only() {
        let target = parse_discovery_target(
            "https://agent.example/keys?generation=2#fragment",
            DiscoveryMechanism::JwksUri,
        )
        .unwrap();
        assert_eq!(
            target.fetch_url.as_str(),
            "https://agent.example/keys?generation=2"
        );
        assert_eq!(target.normalized_identifier, "https://agent.example/keys");
    }

    #[test]
    fn normalized_identifier_uses_url_case_and_default_port_rules() {
        let target = parse_discovery_target(
            "HTTPS://AGENT.EXAMPLE:443/keys?generation=2#fragment",
            DiscoveryMechanism::JwksUri,
        )
        .unwrap();
        assert_eq!(
            target.fetch_url.as_str(),
            "https://agent.example/keys?generation=2"
        );
        assert_eq!(target.normalized_identifier, "https://agent.example/keys");
    }

    #[test]
    fn normalized_identifier_decodes_unreserved_path_escapes_and_removes_dot_segments() {
        let target = parse_discovery_target(
            "https://agent.example/keys/%7e/./current/../final",
            DiscoveryMechanism::JwksUri,
        )
        .unwrap();
        assert_eq!(
            target.normalized_identifier,
            "https://agent.example/keys/~/final"
        );
    }

    #[test]
    fn normalized_identifier_keeps_reserved_path_escapes() {
        let target = parse_discovery_target(
            "https://agent.example/keys/%2f",
            DiscoveryMechanism::JwksUri,
        )
        .unwrap();
        assert_eq!(
            target.normalized_identifier,
            "https://agent.example/keys/%2F"
        );
    }

    #[test]
    fn directory_requires_an_origin() {
        assert!(
            parse_discovery_target("https://agent.example/keys", DiscoveryMechanism::Directory,)
                .is_err()
        );
        let target =
            parse_discovery_target("https://agent.example/", DiscoveryMechanism::Directory)
                .unwrap();
        assert_eq!(target.fetch_url.path(), DIRECTORY_PATH);
    }

    #[test]
    fn thumbprint_is_independent_of_verifier_dependency() {
        assert_eq!(
            Ed25519Jwk::new(X.into()).b64_thumbprint(),
            "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
        );
    }
}
