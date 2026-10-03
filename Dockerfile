# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/cargo-zigbuild:0.19.8@sha256:b3b422171a9e2eacc5e4d5c6eb0d95c2c7e65cad2a62ea6938ae9805ce78df3e AS builder

RUN apt-get update \
    && apt-get install --no-install-recommends --yes clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install 1.97.1 && rustup default 1.97.1
RUN cargo install cargo-auditable --version 0.7.5 --locked

ARG TARGETARCH
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY tests ./tests
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib
RUN case "$TARGETARCH" in \
      amd64) gnu_target=x86_64-unknown-linux-gnu; musl_target=x86_64-unknown-linux-musl ;; \
      arm64) gnu_target=aarch64-unknown-linux-gnu; musl_target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && rustup target add "$gnu_target" "$musl_target" \
    && cargo auditable zigbuild --release --locked -p envoy-web-bot-auth-module --lib --target "$gnu_target" \
    && cargo auditable zigbuild --release --locked -p web-bot-auth-resolver --bin web-bot-auth-resolver --target "$musl_target" \
    && mkdir /out \
    && cp "target/$gnu_target/release/libenvoy_web_bot_auth.so" /out/libenvoy_web_bot_auth.so \
    && cp "target/$musl_target/release/web-bot-auth-resolver" /out/web-bot-auth-resolver

# Publish this target as an OCI artifact and mount it with a Kubernetes image
# volume. It is deliberately not a replacement Envoy image.
FROM scratch AS module-artifact
LABEL org.opencontainers.image.title="Envoy Web Bot Auth module" \
      org.opencontainers.image.description="Envoy dynamic module for Web Bot Auth verification with Ed25519" \
      org.opencontainers.image.url="https://github.com/optimisticmachines/envoy-web-bot-auth" \
      org.opencontainers.image.documentation="https://github.com/optimisticmachines/envoy-web-bot-auth/blob/main/docs/operations.md" \
      org.opencontainers.image.source="https://github.com/optimisticmachines/envoy-web-bot-auth" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /out/libenvoy_web_bot_auth.so /libenvoy_web_bot_auth.so

# Compatibility image for clusters without image volume support.
FROM busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0 AS module-installer
LABEL org.opencontainers.image.title="Envoy Web Bot Auth module installer" \
      org.opencontainers.image.description="Kubernetes init-container fallback for the Envoy Web Bot Auth module" \
      org.opencontainers.image.url="https://github.com/optimisticmachines/envoy-web-bot-auth" \
      org.opencontainers.image.documentation="https://github.com/optimisticmachines/envoy-web-bot-auth/blob/main/docs/operations.md" \
      org.opencontainers.image.source="https://github.com/optimisticmachines/envoy-web-bot-auth" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /out/libenvoy_web_bot_auth.so /opt/web-bot-auth/libenvoy_web_bot_auth.so
USER 65532:65532
ENTRYPOINT ["/bin/sh", "-c", "cp /opt/web-bot-auth/libenvoy_web_bot_auth.so /work/libenvoy_web_bot_auth.so && chmod 0444 /work/libenvoy_web_bot_auth.so"]

FROM scratch AS resolver
LABEL org.opencontainers.image.title="Web Bot Auth resolver" \
      org.opencontainers.image.description="Bounded Web Bot Auth discovery resolver sidecar" \
      org.opencontainers.image.url="https://github.com/optimisticmachines/envoy-web-bot-auth" \
      org.opencontainers.image.documentation="https://github.com/optimisticmachines/envoy-web-bot-auth/blob/main/docs/operations.md" \
      org.opencontainers.image.source="https://github.com/optimisticmachines/envoy-web-bot-auth" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /out/web-bot-auth-resolver /web-bot-auth-resolver
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/web-bot-auth-resolver"]
CMD ["serve"]

# This image is for deterministic kind scenarios only. The fixture feature is
# absent from the production resolver target above.
FROM builder AS kind-fixture-builder
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) musl_target=x86_64-unknown-linux-musl ;; \
      arm64) musl_target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && rustup target add "$musl_target" \
    && cargo auditable zigbuild --release --locked --features kind-fixtures \
      -p web-bot-auth-resolver --bin web-bot-auth-resolver --target "$musl_target" \
    && cp "target/$musl_target/release/web-bot-auth-resolver" /out/web-bot-auth-resolver-fixtures

FROM scratch AS resolver-kind-fixtures
COPY --from=kind-fixture-builder /out/web-bot-auth-resolver-fixtures /web-bot-auth-resolver
USER 65532:65532
ENTRYPOINT ["/web-bot-auth-resolver"]
CMD ["serve-fixtures"]

# Compatibility reference only: the tested Envoy 1.39 runtime.
FROM docker.io/envoyproxy/envoy:distroless-v1.39.1@sha256:eb2c01c13125d1629637cb4e4cce7207009fb7cc2c8027f9742758549d15b6f4 AS compatible-envoy
