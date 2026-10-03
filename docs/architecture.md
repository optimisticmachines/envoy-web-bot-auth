# Architecture

## Protocol profile

This project uses Ed25519 to implement a profile of
[`draft-ietf-webbotauth-httpsig-protocol-00`](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html).
The [IETF Datatracker](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/)
records the current working-group revision and document status.
The module accepts one signature and one identity per request. It supports `directory`,
`jwks_uri`, and `cimd` key discovery.

The module builds on Cloudflare's
[`web-bot-auth`](https://docs.rs/web-bot-auth/0.7.0/web_bot_auth/) Rust crate for
HTTP Message Signature parsing, signature-base construction, JWK handling, and
Ed25519 verification. This project adds Envoy integration, profile
enforcement, key discovery, and admission policy.

The default signature coverage requires `@authority` or `@target-uri` and the
`Signature-Agent` member named by the signed component key. Operators can require
additional supported components: `@method`, `@authority`, `@scheme`,
`@target-uri`, `@path`, `@query`, `signature`, `signature-input`, and
`signature-agent`.

The profile does not verify request bodies, arbitrary HTTP fields, multiple Web
Bot Auth signatures, algorithms other than Ed25519, redistributed key material,
or directory response signatures. Legacy item `Signature-Agent` support is opt
in.

The protocol is an active Internet Draft. This project does not change behavior
automatically when a new revision appears. Each revision requires a normative
review, fixtures, compatibility tests, and an explicit release decision. An RFC
is treated as a new target until it passes the same review.

Known RFC 9421 Ed25519 test keys are rejected unless `--allow-test-keys` is set
for development. This implementation has no nonce store, so a valid signature
can be replayed until its expiry and covered request scope no longer permit it.

## Module-resolver API

The module and resolver exchange JSON protocol defined in repository. Its
`api_version` field is `v1`. This version describes compatibility between those
two components. It does not describe an Ed25519 profile, the project release,
or an IETF draft revision.

The API version changes only when a module and resolver using the old and new
contracts can no longer communicate safely. Reviewing a new IETF draft does not
change the API version unless implementing that draft requires such an
incompatible contract change. The supported algorithm remains explicit in the
`Ed25519Jwk` response type, while `compatibility.toml` records the reviewed IETF
revision.

## Request flow

Envoy removes caller supplied assertion headers, parses the Web Bot Auth fields,
and sends a resolve request to the local resolver unless the optional module
cache has a fresh answer.
The resolver returns either a normalized identifier with an Ed25519 JWK or
authoritative key absence. The module recomputes the identifier and thumbprint
and verifies the signature before emitting trusted headers.

```text
Client request
  |  Signature-Agent, Signature-Input, Signature
  v
Envoy + Web Bot Auth module
  |  remove caller identity headers and parse signed fields
  |  look up answer in optional module cache
  +-- fresh cached answer ---------------------------------------+
  |                                                              |
  v  miss or disabled                                            |
Resolver callout (Unix socket or TCP)                            |
  |  resource cache, then bounded HTTPS discovery when needed    |
  |  Ed25519 JWK and identity, or authoritative key absence      |
  +--------------------------------------------------------------+
  v
Envoy module
  |  check identity and key thumbprint and verify this signature
  +-- verified --------------------> upstream request + trusted identity metadata
  `-- absent, invalid, unavailable -> admission-mode policy result
```

Resolver response errors, callout ID mismatch, identifier mismatch, thumbprint
mismatch, and unusable keys are unavailable results. They never create identity
metadata.

## Resolver and cache

The resolver has separate service, resource, fetch, cache, and limit layers.
Resources are cached by exact fetch URL and kind, not requested key ID. Query is
kept for fetches while normalized identities remove query and fragment. CIMD
metadata and its JWKS are separate resources. Resolution fetches at most one
metadata document and one JWKS document.

[Moka](https://docs.rs/moka/0.12/moka/) caches validated responses and ensures
that concurrent requests for the same resource share one refresh operation.
Standard HTTP caching rules determine when a cached response can be reused,
when to send a conditional request or revalidate it, and when serving a stale
response is allowed. A successful refresh replaces the whole resource. An
eligible transient refresh failure may serve the earlier representation within
its `stale-if-error` window; `must-revalidate` disables that fallback.

[Governor](https://docs.rs/governor/0.10/governor/) applies global, origin, and
resolved address rate limits. Tokio semaphores bound active handlers and outbound
fetches. Per resource circuits and refresh backoff reduce repeated failed work.
These controls are local to each resolver process and pod.

| Limit | Default |
|---|---:|
| Inbound JSON body | 8 KiB |
| Active handlers | 64 |
| Outbound fetches | 32 |
| Global fetch rate and burst | 16 and 32 per second |
| Per origin rate and burst | 2 and 4 per second |
| Per resolved address rate and burst | 8 and 16 per second |
| New origins | 256 per rolling minute |
| Cache, refresh, limiter, circuit entries | 1,024 each |
| Resolution deadline | 1,800 ms |
| Envoy callout timeout | 2,000 ms |

### Optional module cache

The module cache stores selected public keys and identities by discovery
mechanism, fetch URL, and key ID. It is separate from the resolver resource
cache. Requests using the same filter configuration share it across workers.

The resolver reports how long an answer can be reused in
`x-web-bot-auth-cache-valid-for-ms`. If discovery uses multiple documents, the
answer expires when any of them expires. The module can shorten this time but
cannot extend it. Only positive answers that verify the current request are
stored. Cache hits use the same verification, trusted outputs, and admission
policy as resolver responses.

The cache is disabled unless `resolver.cache` is present. It does not combine
concurrent misses, refresh entries in the background, or serve expired entries.

## Egress

Direct mode disables system proxy discovery, validates every DNS answer, rejects
unsafe or mixed answers, and pins the selected address for TLS. Redirects and
response decoding are disabled.

Proxy mode requires `HTTPS_PROXY`, ignores `NO_PROXY`, and has no direct fallback.
The proxy performs final hostname resolution and routing. It is therefore the
SSRF trust boundary and must enforce the required destination policy. The resolver
still validates the requested URL, port, and local DNS answers. It uses platform
trust roots and provides no custom CA setting.

HTTPS port 443 is allowed by default. Additional destination ports require
`--allowed-port`. Discovery responses require accepted JSON media types, identity
encoding, at most 64 KiB, and at most 32 keys.

## Transport and Kubernetes

The standalone resolver defaults to loopback TCP. The Kubernetes sidecar uses a
Unix socket. Socket mode is `0660`. Startup removes only a stale Unix
socket and rejects regular files and symlinks. SIGTERM removes the socket during
graceful shutdown.

The Kubernetes base uses a resolver sidecar, a shared `emptyDir`, UID and GID
65532, `fsGroup: 65532`, and an Envoy pipe cluster. The required overlay adds
readiness gating. Kubernetes 1.34 uses the init container compatibility path.

The optional external-resolver overlay uses TCP through a ClusterIP Service and
a NetworkPolicy instead. It separates the resolver lifecycle from Envoy, but
adds a network hop and a shared failure and trust boundary. The resolver logs a
warning when an explicit non-loopback TCP listener is configured.
