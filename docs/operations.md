# Operations

## Integration model

Envoy Gateway loads this component as a dynamic module. See the
[Envoy Gateway dynamic modules guide](https://gateway.envoyproxy.io/latest/tasks/extensibility/dynamic-modules/).
This project extends an existing Envoy Gateway deployment. It does not install
or operate Envoy Gateway. Use an Envoy Gateway and Envoy runtime combination
from [`compatibility.toml`](../compatibility.toml).

Releases publish these OCI artifacts with immutable digests and provenance
attestations:

| Artifact | Image | Purpose |
|---|---|---|
| Module | `ghcr.io/michalskalski/envoy-web-bot-auth-module` | Image volume containing the dynamic module library |
| Resolver | `ghcr.io/michalskalski/envoy-web-bot-auth-resolver` | Resolver workload image |
| Installer | `ghcr.io/michalskalski/envoy-web-bot-auth-module-installer` | Compatibility init container image |

Pin a release digest in the operator managed deployment. The module image is
not a runnable container.

Register the shared library in the `EnvoyProxy` dynamic module list, make it
available to Envoy, then use an `EnvoyExtensionPolicy` to attach it to a Gateway
or HTTPRoute. The module's `resolver.cluster` must name an Envoy cluster that
reaches the resolver.

The resolver can run as a sidecar over a shared UDS socket or as an operator
managed service. The sidecar keeps the resolver local. Service replicas have
independent in memory caches and expose an unauthenticated resolver API, so the
operator must restrict its network access.

The [Kind integration manifest](../examples/kind/resources.yaml) demonstrates
the UDS sidecar wiring, module registration, resolver cluster, and policy
attachment. It also creates a dedicated GatewayClass, Gateway, and Echo backend
and uses locally loaded development images. Incorporate the relevant EnvoyProxy
and policy configuration into the operator managed Gateway deployment.

## Configuration

Unknown module fields are rejected. Resolver options are validated at startup.
`web-bot-auth-resolver serve --help` lists every command line option.

### Module

Set module fields under `EnvoyExtensionPolicy.spec.dynamicModule[].config`, or
under the Dynamic Module HTTP filter's `filter_config.value` in standalone
Envoy.

| Field | Default | Meaning |
|---|---|---|
| `mode` | `observe` | `observe`, `optional`, or `required` |
| `resolver.cluster` | `web-bot-auth-key-resolver` | Envoy cluster for the resolver |
| `resolver.timeout_ms` | `2000` | Callout timeout, from 1 to 2000 ms |
| `resolver.cache` | absent | Enable reuse of verified resolver answers |
| `resolver.cache.max_entries` | `1024` | Cache capacity target, from 1 to 4096 entries |
| `resolver.cache.max_ttl_ms` | `5000` | Maximum reuse time, from 1 to 60000 ms |
| `max_signature_lifetime_seconds` | `86400` | Maximum accepted signature lifetime |
| `clock_skew_seconds` | `5` | Accepted future clock skew |
| `required_components` | `[]` | Components every signature must cover |
| `accept_legacy_signature_agent` | `false` | Accept the older `Signature-Agent` item form |
| `forward_identity_headers` | `true` | Send trusted status, identity, and key ID headers downstream |

For repeated requests using the same discovery resource and key, the module
cache can avoid resolver callouts while the answer is fresh. Enable it with:

```yaml
resolver:
  cluster: web-bot-auth-key-resolver
  timeout_ms: 2000
  cache:
    max_entries: 1024
    max_ttl_ms: 5000
```

The cache is disabled when `resolver.cache` is absent. `cache: {}` uses the
defaults above. Each filter configuration has its own cache, shared across
Envoy workers.

An answer is stored only after signature verification succeeds. The cache keeps
it for up to `max_ttl_ms`, but never longer than the resolver allows. Reads do
not extend that time.
Every request still verifies its signature. Missing keys, failures, stale
answers, and resources with `no-cache` or `no-store` are not cached.

By default, verification requires `@authority` or `@target-uri` and the
matching `Signature-Agent` member. `required_components` accepts only
`@method`, `@authority`, `@scheme`, `@target-uri`, `@path`, `@query`,
`signature`, `signature-input`, and `signature-agent`.

### Trusted outputs

The module removes these inbound headers before parsing, so callers cannot set
them for an upstream service.

| Header | When present | Meaning |
|---|---|---|
| `x-web-bot-auth-status` | Header forwarding enabled | Verification outcome |
| `x-web-bot-auth-identity` | Verified request | Normalized identifier |
| `x-web-bot-auth-keyid` | Verified request | Ed25519 JWK thumbprint |

When `forward_identity_headers` is true, the module sets the status header for
every outcome and identity and key ID only for verified requests. Dynamic
metadata is always available under `envoy.filters.http.web_bot_auth` with
`status`, `reason`, and `verified`. Verified requests also include `identity`
and `keyid`.

### Resolver

| Option | Default | Meaning |
|---|---|---|
| `--listen` | `tcp://127.0.0.1:8081` | TCP address or Unix socket URI. Non loopback TCP exposes an unauthenticated API. |
| `--egress-mode` | `direct` | `direct` or `proxy` |
| `--allowed-port` | `443` | Repeat to allow destination ports |
| `--allow-test-keys` | off | Permit known RFC test keys for development |
| `--resolution-timeout-ms` | `1800` | End to end resolver budget |
| `--inbound-body-bytes` | `8192` | Maximum resolver JSON request body |
| `--active-handlers` | `64` | Maximum concurrent handlers |
| `--outbound-fetches` | `32` | Maximum concurrent discovery fetches |
| `--state-entries` | `1024` | Maximum entries in each cache and control store |
| `--max-keys` | `32` | Maximum JWKs in one response |

The rate and burst options are `--global-fetch-rate`, `--global-fetch-burst`,
`--origin-fetch-rate`, `--origin-fetch-burst`, `--ip-fetch-rate`, and
`--ip-fetch-burst`. Burst values must be at least their matching rate.
`--new-origins-per-minute` defaults to `256`.

Direct mode rejects proxy environment variables, validates DNS answers, and
pins the selected address. Proxy mode requires uppercase `HTTPS_PROXY`, rejects
conflicting proxy variables, ignores `NO_PROXY`, and never falls back to direct
egress. The proxy enforces the final destination policy. Discovery requires
HTTPS. Port 443 is allowed by default. Redirects and content decoding are
disabled.

### Metric export

The resolver emits no OpenTelemetry data unless an endpoint is set:

```yaml
- name: OTEL_EXPORTER_OTLP_METRICS_ENDPOINT
  value: http://collector.observability.svc:4317
- name: OTEL_METRIC_EXPORT_INTERVAL
  value: "5000"
```

The resolver exports OTLP over gRPC to the configured endpoint and uses system
trust roots. Envoy metric export is configured separately at
`EnvoyProxy.spec.telemetry.metrics.sinks`.

`metrics_exporter_enabled` confirms resolver exporter setup. Verify delivery at
the Collector or backend.

## Metrics

| Series | Unit | Labels | Meaning |
|---|---|---|---|
| `dynamicmodulescustom.requests` | count | `outcome`, `reason` | Module verification outcomes. Use this instead of HTTP status in observe mode. |
| `dynamicmodulescustom.web_bot_auth_duration_us` | microseconds | `phase`, `result` | Module phase latency. |
| `dynamicmodulescustom.resolver_cache_events` | count | `event` | Module cache `hit`, `miss`, `insert`, and `not_cacheable` events. |
| `web_bot_auth.resolver.resolutions` | `{request}` | `result` | Completed resolver requests. |
| `web_bot_auth.resolver.resolution.duration` | `s` | `result` | Full admitted resolver request duration. |
| `web_bot_auth.resolver.cache.events` | `{event}` | `event` | `fresh_hit`, `refresh`, `stale_on_error`, and `error`. |
| `web_bot_auth.resolver.fetches` | `{fetch}` | `result` | Completed outbound discovery fetches. |
| `web_bot_auth.resolver.fetch.duration` | `s` | `result` | Outbound discovery fetch duration. |

Resolver histograms have boundaries from 25 microseconds to 2 seconds. Values
above 2 seconds are overflow. `resolver_send` measures issuing the Envoy
callout. `resolver_callout` starts before that step and ends in the response
callback, so it already includes `resolver_send`. Do not add them.
`resolver_cache_lookup` measures the module lookup. Cache hits do
not emit `resolver_send` or `resolver_callout`, but still emit
`response_verify`.
