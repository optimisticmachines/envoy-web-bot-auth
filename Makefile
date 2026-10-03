SHELL := /usr/bin/env bash

CLUSTER_NAME ?= envoy-web-bot-auth
KIND_NODE_IMAGE ?=
KIND_KUBECONFIG ?= $(CURDIR)/.kind/$(CLUSTER_NAME).kubeconfig
export KIND_KUBECONFIG
MODULE_IMAGE ?= envoy-web-bot-auth-module:dev
RESOLVER_IMAGE ?= envoy-web-bot-auth-resolver:dev
FIXTURE_RESOLVER_IMAGE ?= envoy-web-bot-auth-resolver-fixtures:dev
MODULE_INSTALLER_IMAGE ?= envoy-web-bot-auth-module-installer:dev
RELEASE_DIR ?= $(CURDIR)/dist
RELEASE_STAGING ?= $(CURDIR)/.release-staging
RELEASE_VERSION ?= $(shell cargo metadata --no-deps --format-version 1 2>/dev/null | jq -r '.packages[] | select(.name == "envoy-web-bot-auth-module") | .version' | head -n1)
RELEASE_TAG ?= v$(RELEASE_VERSION)
RELEASE_REPOSITORY ?= $(or $(GITHUB_REPOSITORY),optimisticmachines/envoy-web-bot-auth)
ENVOY_LINE ?= $(shell sed -n 's/^envoy_runtime = "distroless-v\([0-9][0-9]*\.[0-9][0-9]*\).*/envoy\1/p' compatibility.toml)
EG_VERSION ?= v1.9.1
EG_NAMESPACE ?= envoy-gateway-system
GATEWAY_NAMESPACE ?= default
GATEWAY_NAME ?= web-bot-auth
MANIFESTS ?= examples/kind/resources.yaml
PORT_FORWARD_PORT ?= 8888
MODE ?= observe
RATE_LIMIT_NAMESPACE ?= web-bot-auth-rate-limit
ENVOY_SERVICE_SELECTOR = gateway.envoyproxy.io/owning-gateway-namespace=$(GATEWAY_NAMESPACE),gateway.envoyproxy.io/owning-gateway-name=$(GATEWAY_NAME)
KUBECTL = kubectl --kubeconfig '$(KIND_KUBECONFIG)'
HELM = helm --kubeconfig '$(KIND_KUBECONFIG)'

.DEFAULT_GOAL := help

.PHONY: help check-tools check-buildx check-release-tools metadata-test test integration-test transport-test manifest-check cluster image fixture-image module-installer-image multiarch release-metadata release-archives release-manifest sbom release-verify release-artifacts-verify load-image load-fixture-image load-module-installer-image gateway up kind-up kind-apply kind-fixture-up kind-rate-limit-up kind-composition-apply clean-kind-artifacts kind-auth-test kind-composition-test kind-test kind-external-resolver-test kind-portability-test kind-status kind-logs kind-diagnostics kind-forward reload port-forward status down kind-down

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "%-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

check-tools: ## Check that the local cluster tooling is installed.
	@for tool in docker kind helm kubectl; do \
		command -v $$tool >/dev/null || { echo "missing required tool: $$tool" >&2; exit 1; }; \
	done

check-buildx: ## Check multi-architecture image tooling.
	@command -v docker >/dev/null || { echo "missing required tool: docker" >&2; exit 1; }
	@docker buildx version >/dev/null

check-release-tools: check-buildx ## Check SBOM tooling.
	@for tool in syft skopeo jq; do \
		command -v $$tool >/dev/null || { echo "missing required tool: $$tool" >&2; exit 1; }; \
	done

metadata-test: ## Check release metadata validation.
	cargo test --locked -p web-bot-auth-test-harness --bin release-metadata

test: ## Run formatting, unit, and lint gates.
	cargo fmt --all -- --check
	cargo test --locked --workspace --all-targets
	cargo test --locked -p web-bot-auth-resolver --bin web-bot-auth-resolver -- --ignored
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

integration-test: ## Run resolver transport and fixture integration tests.
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --all-targets
	cargo test --locked -p web-bot-auth-resolver --features kind-fixtures --bin web-bot-auth-resolver -- --ignored fixture_control_updates_the_fixture_over_uds
	cargo test --locked -p web-bot-auth-resolver --test http

transport-test: ## Run live TLS and explicit proxy tests.
	cargo test --locked -p web-bot-auth-resolver --lib -- --ignored --nocapture

manifest-check: ## Render the Kubernetes reference configurations.
	kubectl kustomize examples/kind >/dev/null
	kubectl kustomize examples/kind/overlays/required --load-restrictor=LoadRestrictionsNone >/dev/null
	kubectl kustomize examples/kind/overlays/external-resolver --load-restrictor=LoadRestrictionsNone >/dev/null
	kubectl kustomize examples/kind/overlays/external-resolver-fixtures --load-restrictor=LoadRestrictionsNone >/dev/null
	kubectl kustomize examples/kind/composition --load-restrictor=LoadRestrictionsNone >/dev/null

multiarch: check-buildx ## Build amd64/arm64 OCI archives without publishing.
	mkdir --parents '$(RELEASE_DIR)'
	docker buildx build --platform linux/amd64,linux/arm64 --target module-artifact \
		--output 'type=oci,dest=$(RELEASE_DIR)/module.oci.tar' .
	docker buildx build --platform linux/amd64,linux/arm64 --target module-installer \
		--output 'type=oci,dest=$(RELEASE_DIR)/module-installer.oci.tar' .
	docker buildx build --platform linux/amd64,linux/arm64 --target resolver \
		--output 'type=oci,dest=$(RELEASE_DIR)/resolver.oci.tar' .

release-metadata: ## Generate compatibility metadata for the current release.
	mkdir --parents '$(RELEASE_DIR)'
	cargo run --locked -p web-bot-auth-test-harness --bin release-metadata -- \
		--tag '$(RELEASE_TAG)' \
		--repository '$(RELEASE_REPOSITORY)' \
		--output '$(RELEASE_DIR)/compatibility.json'

release-archives: check-buildx release-metadata ## Build architecture specific release archives without publishing.
	rm -rf '$(RELEASE_STAGING)'
	mkdir --parents '$(RELEASE_STAGING)' '$(RELEASE_DIR)'
	@set -euo pipefail; \
	for platform in linux/amd64 linux/arm64; do \
		arch="$${platform##*/}"; \
		module_stage='$(RELEASE_STAGING)/module-'"$$arch"; \
		resolver_stage='$(RELEASE_STAGING)/resolver-'"$$arch"; \
		mkdir --parents "$$module_stage" "$$resolver_stage"; \
		docker buildx build --platform "$$platform" --target module-artifact \
			--output "type=local,dest=$$module_stage" .; \
		docker buildx build --platform "$$platform" --target resolver \
			--output "type=local,dest=$$resolver_stage" .; \
		test -s "$$module_stage/libenvoy_web_bot_auth.so"; \
		test -s "$$resolver_stage/web-bot-auth-resolver"; \
		cp LICENSE "$$module_stage/LICENSE"; \
		cp LICENSE "$$resolver_stage/LICENSE"; \
		cp release/module-README.txt "$$module_stage/README.txt"; \
		cp release/resolver-README.txt "$$resolver_stage/README.txt"; \
		cp '$(RELEASE_DIR)/compatibility.json' "$$module_stage/compatibility.json"; \
		cp '$(RELEASE_DIR)/compatibility.json' "$$resolver_stage/compatibility.json"; \
		tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 1970-01-01' \
			-czf '$(RELEASE_DIR)/envoy-web-bot-auth-module-$(RELEASE_VERSION)-$(ENVOY_LINE)-linux-'"$$arch"'.tar.gz' \
			-C "$$module_stage" libenvoy_web_bot_auth.so compatibility.json LICENSE README.txt; \
		tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 1970-01-01' \
			-czf '$(RELEASE_DIR)/web-bot-auth-resolver-$(RELEASE_VERSION)-linux-'"$$arch"'.tar.gz' \
			-C "$$resolver_stage" web-bot-auth-resolver compatibility.json LICENSE README.txt; \
	done

release-manifest: release-archives sbom ## Write the release asset manifest.
	@set -euo pipefail; \
	assets=( \
		'envoy-web-bot-auth-module-$(RELEASE_VERSION)-$(ENVOY_LINE)-linux-amd64.tar.gz' \
		'envoy-web-bot-auth-module-$(RELEASE_VERSION)-$(ENVOY_LINE)-linux-arm64.tar.gz' \
		'web-bot-auth-resolver-$(RELEASE_VERSION)-linux-amd64.tar.gz' \
		'web-bot-auth-resolver-$(RELEASE_VERSION)-linux-arm64.tar.gz' \
		module.oci.tar module-installer.oci.tar resolver.oci.tar \
		module-amd64.spdx.json module-arm64.spdx.json \
		module-installer-amd64.spdx.json module-installer-arm64.spdx.json \
		resolver-amd64.spdx.json resolver-arm64.spdx.json compatibility.json \
	); \
	for asset in "$${assets[@]}"; do test -f '$(RELEASE_DIR)/'"$$asset"; done; \
	checksums="$$(cd '$(RELEASE_DIR)' && for asset in "$${assets[@]}"; do sha256sum "$$asset"; done)"; \
	printf '%s\n' "$$checksums" | jq -Rsc '[split("\n")[] | select(length > 0) | split("  ") | {name: .[1], sha256: .[0]}]' > '$(RELEASE_STAGING)/assets.json'; \
	jq -n \
		--arg schema_version '1' \
		--arg tag '$(RELEASE_TAG)' \
		--arg version '$(RELEASE_VERSION)' \
		--arg envoy_line '$(ENVOY_LINE)' \
		--argjson compatibility "$$(jq '.compatibility' '$(RELEASE_DIR)/compatibility.json')" \
		--argjson assets "$$(cat '$(RELEASE_STAGING)/assets.json')" \
		'{schema_version: ($$schema_version | tonumber), tag: $$tag, version: $$version, envoy_compatibility: $$envoy_line, compatibility: $$compatibility, assets: $$assets}' \
		> '$(RELEASE_DIR)/release-manifest.json'

sbom: multiarch ## Generate SPDX JSON SBOMs for every OCI archive.
	syft 'oci-archive:$(RELEASE_DIR)/module.oci.tar' --platform linux/amd64 --select-catalogers '+cargo-auditable-binary-cataloger' --output 'spdx-json=$(RELEASE_DIR)/module-amd64.spdx.json'
	syft 'oci-archive:$(RELEASE_DIR)/module.oci.tar' --platform linux/arm64 --select-catalogers '+cargo-auditable-binary-cataloger' --output 'spdx-json=$(RELEASE_DIR)/module-arm64.spdx.json'
	syft 'oci-archive:$(RELEASE_DIR)/module-installer.oci.tar' --platform linux/amd64 --select-catalogers '+cargo-auditable-binary-cataloger' --output 'spdx-json=$(RELEASE_DIR)/module-installer-amd64.spdx.json'
	syft 'oci-archive:$(RELEASE_DIR)/module-installer.oci.tar' --platform linux/arm64 --select-catalogers '+cargo-auditable-binary-cataloger' --output 'spdx-json=$(RELEASE_DIR)/module-installer-arm64.spdx.json'
	syft 'oci-archive:$(RELEASE_DIR)/resolver.oci.tar' --platform linux/amd64 --select-catalogers '+cargo-auditable-binary-cataloger' --output 'spdx-json=$(RELEASE_DIR)/resolver-amd64.spdx.json'
	syft 'oci-archive:$(RELEASE_DIR)/resolver.oci.tar' --platform linux/arm64 --select-catalogers '+cargo-auditable-binary-cataloger' --output 'spdx-json=$(RELEASE_DIR)/resolver-arm64.spdx.json'

release-verify: test manifest-check check-release-tools ## Run all local release gates; kind scenarios remain a separate required gate.
	cargo deny check --warn unmaintained
	$(MAKE) release-artifacts-verify

release-artifacts-verify: release-manifest ## Verify release artifacts after the Rust, manifest, and tool checks pass.
	@set -euo pipefail; \
	for archive in \
		'$(RELEASE_DIR)/envoy-web-bot-auth-module-$(RELEASE_VERSION)-$(ENVOY_LINE)-linux-amd64.tar.gz' \
		'$(RELEASE_DIR)/envoy-web-bot-auth-module-$(RELEASE_VERSION)-$(ENVOY_LINE)-linux-arm64.tar.gz' \
		'$(RELEASE_DIR)/web-bot-auth-resolver-$(RELEASE_VERSION)-linux-amd64.tar.gz' \
		'$(RELEASE_DIR)/web-bot-auth-resolver-$(RELEASE_VERSION)-linux-arm64.tar.gz'; do \
		tar --list --file "$$archive" >/dev/null; \
		tar --list --file "$$archive" | awk 'NF != 1 || $$0 ~ /^\// || $$0 ~ /\.\./ { exit 1 }'; \
		tar --list --file "$$archive" | sort | grep --fixed-strings --line-regexp compatibility.json >/dev/null; \
		tar --list --file "$$archive" | sort | grep --fixed-strings --line-regexp LICENSE >/dev/null; \
		tar --list --file "$$archive" | sort | grep --fixed-strings --line-regexp README.txt >/dev/null; \
	done
	@set -euo pipefail; \
	verify_module_symbols() { \
		module="$$1"; \
		nm -D --defined-only "$$module" | awk '{print $$3}' | grep --fixed-strings --line-regexp envoy_dynamic_module_on_program_init >/dev/null; \
		nm -D --defined-only "$$module" | awk '{print $$3}' | grep --fixed-strings --line-regexp envoy_dynamic_module_on_http_filter_config_new >/dev/null; \
		nm -D --defined-only "$$module" | awk '{print $$3}' | grep --fixed-strings --line-regexp envoy_dynamic_module_on_http_filter_new >/dev/null; \
	}; \
	for arch in amd64 arm64; do \
		module_archive='$(RELEASE_DIR)/envoy-web-bot-auth-module-$(RELEASE_VERSION)-$(ENVOY_LINE)-linux-'"$$arch"'.tar.gz'; \
		resolver_archive='$(RELEASE_DIR)/web-bot-auth-resolver-$(RELEASE_VERSION)-linux-'"$$arch"'.tar.gz'; \
		dir="$$(mktemp -d)"; \
		trap 'rm -rf "$$dir"' EXIT; \
		mkdir --parents "$$dir/module" "$$dir/resolver"; \
		tar --extract --file "$$module_archive" --directory "$$dir/module"; \
		tar --extract --file "$$resolver_archive" --directory "$$dir/resolver"; \
		case "$$arch" in \
			amd64) expected_machine='Advanced Micro Devices X86-64' ;; \
			arm64) expected_machine='AArch64' ;; \
			*) exit 1 ;; \
		esac; \
		file -b "$$dir/module/libenvoy_web_bot_auth.so" | grep --fixed-strings --ignore-case 'ELF 64-bit' >/dev/null; \
		file -b "$$dir/module/libenvoy_web_bot_auth.so" | grep --fixed-strings --ignore-case 'shared object' >/dev/null; \
		readelf --file-header "$$dir/module/libenvoy_web_bot_auth.so" | grep --fixed-strings "$$expected_machine" >/dev/null; \
		readelf --file-header "$$dir/module/libenvoy_web_bot_auth.so" | grep --extended-regexp 'Type:[[:space:]]+DYN \(Shared object file\)' >/dev/null; \
		verify_module_symbols "$$dir/module/libenvoy_web_bot_auth.so"; \
		file -b "$$dir/resolver/web-bot-auth-resolver" | grep --fixed-strings --ignore-case 'ELF 64-bit' >/dev/null; \
		file -b "$$dir/resolver/web-bot-auth-resolver" | grep --fixed-strings --ignore-case 'statically linked' >/dev/null; \
		readelf --file-header "$$dir/resolver/web-bot-auth-resolver" | grep --fixed-strings "$$expected_machine" >/dev/null; \
		if readelf --program-headers "$$dir/resolver/web-bot-auth-resolver" | grep --fixed-strings 'INTERP' >/dev/null; then \
			echo "resolver archive is dynamically linked: $$arch" >&2; exit 1; \
		fi; \
		cmp --silent "$$dir/module/compatibility.json" '$(RELEASE_DIR)/compatibility.json'; \
		cmp --silent "$$dir/resolver/compatibility.json" '$(RELEASE_DIR)/compatibility.json'; \
		rm -rf "$$dir"; \
		trap - EXIT; \
	done
	@set -euo pipefail; \
	compatible_image='envoy-web-bot-auth-compatible:$(ENVOY_LINE)'; \
	docker build --platform linux/amd64 --target compatible-envoy --tag "$$compatible_image" . >/dev/null; \
	validation_dir='$(RELEASE_STAGING)/envoy-validation'; \
	trap 'rm -rf "$$validation_dir"' EXIT; \
	rm -rf "$$validation_dir"; \
	mkdir --parents "$$validation_dir/dynamic-modules"; \
	cp '$(CURDIR)/examples/standalone/envoy.yaml' "$$validation_dir/envoy.yaml"; \
	tar --extract --file '$(RELEASE_DIR)/envoy-web-bot-auth-module-$(RELEASE_VERSION)-$(ENVOY_LINE)-linux-amd64.tar.gz' \
		--directory "$$validation_dir/dynamic-modules" libenvoy_web_bot_auth.so; \
	chmod 755 '$(RELEASE_STAGING)' "$$validation_dir" "$$validation_dir/dynamic-modules"; \
	chmod 644 "$$validation_dir/envoy.yaml" "$$validation_dir/dynamic-modules/libenvoy_web_bot_auth.so"; \
	docker run --rm --entrypoint /usr/local/bin/envoy \
		--volume "$$validation_dir:/etc/envoy:ro,z" \
		"$$compatible_image" --mode validate --config-path /etc/envoy/envoy.yaml >/dev/null
	@jq --exit-status \
		--arg tag '$(RELEASE_TAG)' \
		--arg version '$(RELEASE_VERSION)' \
		--arg envoy_line '$(ENVOY_LINE)' \
		'.schema_version == 1 and .tag == $$tag and .version == $$version and .envoy_compatibility == $$envoy_line and (.assets | length) == 14' \
		'$(RELEASE_DIR)/release-manifest.json' >/dev/null
	@skopeo inspect --raw 'oci-archive:$(RELEASE_DIR)/module.oci.tar' | jq --exit-status '[.manifests[] | select(.platform.os == "linux" and (.platform.architecture == "amd64" or .platform.architecture == "arm64"))] | map(.platform.architecture) | sort == ["amd64", "arm64"]' >/dev/null
	@skopeo inspect --raw 'oci-archive:$(RELEASE_DIR)/module-installer.oci.tar' | jq --exit-status '[.manifests[] | select(.platform.os == "linux" and (.platform.architecture == "amd64" or .platform.architecture == "arm64"))] | map(.platform.architecture) | sort == ["amd64", "arm64"]' >/dev/null
	@skopeo inspect --raw 'oci-archive:$(RELEASE_DIR)/resolver.oci.tar' | jq --exit-status '[.manifests[] | select(.platform.os == "linux" and (.platform.architecture == "amd64" or .platform.architecture == "arm64"))] | map(.platform.architecture) | sort == ["amd64", "arm64"]' >/dev/null
	@jq --exit-status '[.packages[] | select(.name == "envoy-web-bot-auth-module")] | length > 0' '$(RELEASE_DIR)/module-amd64.spdx.json' >/dev/null
	@jq --exit-status '[.packages[] | select(.name == "envoy-web-bot-auth-module")] | length > 0' '$(RELEASE_DIR)/module-arm64.spdx.json' >/dev/null
	@jq --exit-status '[.packages[] | select(.name == "envoy-web-bot-auth-module")] | length > 0' '$(RELEASE_DIR)/module-installer-amd64.spdx.json' >/dev/null
	@jq --exit-status '[.packages[] | select(.name == "envoy-web-bot-auth-module")] | length > 0' '$(RELEASE_DIR)/module-installer-arm64.spdx.json' >/dev/null
	@jq --exit-status '[.packages[] | select(.name == "web-bot-auth-resolver")] | length > 0' '$(RELEASE_DIR)/resolver-amd64.spdx.json' >/dev/null
	@jq --exit-status '[.packages[] | select(.name == "web-bot-auth-resolver")] | length > 0' '$(RELEASE_DIR)/resolver-arm64.spdx.json' >/dev/null
	(cd '$(RELEASE_DIR)' && sha256sum module.oci.tar module-installer.oci.tar resolver.oci.tar) \
		> '$(RELEASE_DIR)/archive-checksums.sha256'
	@set -euo pipefail; \
	{ \
		skopeo inspect --raw 'oci-archive:$(RELEASE_DIR)/module.oci.tar' | sha256sum | sed 's/  -$$/  module.oci.index.json/'; \
		skopeo inspect --raw 'oci-archive:$(RELEASE_DIR)/module-installer.oci.tar' | sha256sum | sed 's/  -$$/  module-installer.oci.index.json/'; \
		skopeo inspect --raw 'oci-archive:$(RELEASE_DIR)/resolver.oci.tar' | sha256sum | sed 's/  -$$/  resolver.oci.index.json/'; \
	} > '$(RELEASE_DIR)/oci-index-digests.sha256'
	@test "$$(wc -l < '$(RELEASE_DIR)/oci-index-digests.sha256')" -eq 3
	@awk 'NF != 2 || length($$1) != 64 { exit 1 }' '$(RELEASE_DIR)/oci-index-digests.sha256'
	@set -euo pipefail; \
	(cd '$(RELEASE_DIR)' && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | sort | xargs sha256sum) \
		> '$(RELEASE_DIR)/SHA256SUMS'

cluster: check-tools ## Create the local kind cluster if it does not already exist.
	@mkdir --parents '$(dir $(KIND_KUBECONFIG))'
	@if kind get clusters | grep -Fxq '$(CLUSTER_NAME)'; then \
		echo "kind cluster $(CLUSTER_NAME) already exists"; \
		kind export kubeconfig --name '$(CLUSTER_NAME)' --kubeconfig '$(KIND_KUBECONFIG)'; \
	else \
		kind create cluster --name '$(CLUSTER_NAME)' --kubeconfig '$(KIND_KUBECONFIG)' $(if $(KIND_NODE_IMAGE),--image '$(KIND_NODE_IMAGE)'); \
	fi

image: check-tools ## Build the module OCI artifact and resolver sidecar image.
	docker build --target module-artifact --tag '$(MODULE_IMAGE)' .
	docker build --target resolver --tag '$(RESOLVER_IMAGE)' .

fixture-image: check-tools ## Build the feature-gated resolver used only by kind scenarios.
	docker build --target resolver-kind-fixtures --tag '$(FIXTURE_RESOLVER_IMAGE)' .

module-installer-image: check-tools ## Build the init-container module loader used by compatibility tests.
	docker build --target module-installer --tag '$(MODULE_INSTALLER_IMAGE)' .

load-image: cluster image ## Load the local Envoy image into kind.
	kind load docker-image --name '$(CLUSTER_NAME)' '$(MODULE_IMAGE)' '$(RESOLVER_IMAGE)'

load-fixture-image: cluster fixture-image ## Load the feature-gated fixture resolver into kind.
	kind load docker-image --name '$(CLUSTER_NAME)' '$(FIXTURE_RESOLVER_IMAGE)'

load-module-installer-image: cluster module-installer-image ## Load the init-container module loader into kind.
	kind load docker-image --name '$(CLUSTER_NAME)' '$(MODULE_INSTALLER_IMAGE)'

gateway: load-image ## Install or upgrade Envoy Gateway
	$(HELM) upgrade --install envoy-gateway oci://docker.io/envoyproxy/gateway-helm \
		--version '$(EG_VERSION)' \
		--namespace '$(EG_NAMESPACE)' \
		--create-namespace \
		--wait \
		--timeout 5m
	$(KUBECTL) rollout status deployment/envoy-gateway --namespace '$(EG_NAMESPACE)' --timeout=5m

up: gateway ## Create the cluster, build/load the image, install Envoy Gateway, and apply local resources.
	$(KUBECTL) apply --filename '$(MANIFESTS)'
	$(KUBECTL) wait --for=condition=Accepted gateway/'$(GATEWAY_NAME)' --namespace '$(GATEWAY_NAMESPACE)' --timeout=5m
	$(KUBECTL) rollout status deployment --namespace '$(EG_NAMESPACE)' \
		--selector '$(ENVOY_SERVICE_SELECTOR)' --timeout=5m
	$(KUBECTL) rollout status deployment/echo --namespace '$(GATEWAY_NAMESPACE)' --timeout=5m

kind-up: gateway ## Prepare the persistent kind cluster and install Envoy Gateway.

kind-apply: kind-up load-fixture-image ## Apply one persistent fixture mode. Use MODE=observe, optional, or required.
	@case '$(MODE)' in observe|optional|required) ;; *) echo 'MODE must be observe, optional, or required' >&2; exit 1 ;; esac
	kubectl kustomize 'examples/kind/overlays/$(MODE)' --load-restrictor=LoadRestrictionsNone | $(KUBECTL) apply --filename -
	$(KUBECTL) rollout status deployment --namespace '$(EG_NAMESPACE)' \
		--selector '$(ENVOY_SERVICE_SELECTOR)' --timeout=5m

kind-fixture-up: kind-apply ## Apply the persistent observe mode with deterministic fixtures.

kind-rate-limit-up: kind-up load-fixture-image ## Install Redis and enable Envoy Gateway global rate limiting.
	$(KUBECTL) apply --filename examples/kind/composition/redis.yaml
	$(KUBECTL) rollout status deployment/redis --namespace '$(RATE_LIMIT_NAMESPACE)' --timeout=180s
	$(HELM) upgrade --install envoy-gateway oci://docker.io/envoyproxy/gateway-helm \
		--version '$(EG_VERSION)' \
		--namespace '$(EG_NAMESPACE)' \
		--reuse-values \
		--set config.envoyGateway.rateLimit.backend.type=Redis \
		--set config.envoyGateway.rateLimit.backend.redis.url=redis.$(RATE_LIMIT_NAMESPACE).svc.cluster.local:6379 \
		--set config.envoyGateway.rateLimit.failClosed=false \
		--wait \
		--timeout 5m
	$(KUBECTL) rollout status deployment/envoy-gateway --namespace '$(EG_NAMESPACE)' --timeout=5m

kind-composition-apply: kind-rate-limit-up ## Apply isolated authorization and rate-limit routes.
	kubectl kustomize examples/kind/composition --load-restrictor=LoadRestrictionsNone | $(KUBECTL) apply --filename -
	$(KUBECTL) rollout status deployment --namespace '$(EG_NAMESPACE)' \
		--selector '$(ENVOY_SERVICE_SELECTOR)' --timeout=5m

clean-kind-artifacts: ## Remove artifacts from previous kind test runs.
	rm -rf -- target/e2e-artifacts

kind-auth-test: kind-apply ## Run the authentication kind scenarios.
	$(MAKE) clean-kind-artifacts
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --test kind_e2e -- --ignored --nocapture --test-threads=1 admission_and_resolver_failure_matrix

kind-composition-test: kind-composition-apply ## Run Envoy authorization and rate-limit composition scenarios.
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --test kind_e2e -- --ignored --nocapture --test-threads=1 envoy_security_policy_consumes_verified_identity
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --test kind_e2e -- --ignored --nocapture --test-threads=1 local_rate_limit_is_per_proxy_and_not_identity_keyed
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --test kind_e2e -- --ignored --nocapture --test-threads=1 global_rate_limit_shares_identity_across_proxies

kind-test: kind-apply ## Run all kind scenarios and keep the cluster for inspection.
	$(MAKE) kind-composition-apply
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --test kind_e2e -- --ignored --nocapture --test-threads=1 admission_and_resolver_failure_matrix
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --test kind_e2e -- --ignored --nocapture --test-threads=1 rotation_replaces_removed_keys
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --test kind_e2e -- --ignored --nocapture --test-threads=1 resolver_sidecar_restart_recovers
	$(MAKE) kind-composition-test

kind-external-resolver-test: kind-up load-fixture-image ## Verify the resolver Service topology.
	$(MAKE) clean-kind-artifacts
	kubectl kustomize examples/kind/overlays/external-resolver-fixtures --load-restrictor=LoadRestrictionsNone | $(KUBECTL) apply --filename -
	$(KUBECTL) rollout status deployment/web-bot-auth-resolver --namespace '$(GATEWAY_NAMESPACE)' --timeout=5m
	$(KUBECTL) rollout status deployment --namespace '$(EG_NAMESPACE)' \
		--selector '$(ENVOY_SERVICE_SELECTOR)' --timeout=5m
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --test kind_e2e -- --ignored --nocapture --test-threads=1 external_resolver_service_verifies_request

kind-portability-test: kind-up load-fixture-image load-module-installer-image ## Run the module loading compatibility scenario.
	kubectl kustomize examples/kind/overlays/init-container --load-restrictor=LoadRestrictionsNone | $(KUBECTL) apply --filename -
	$(KUBECTL) rollout status deployment --namespace '$(EG_NAMESPACE)' \
		--selector '$(ENVOY_SERVICE_SELECTOR)' --timeout=5m
	cargo test --locked -p web-bot-auth-test-harness --features kind-fixtures --test kind_e2e -- --ignored --nocapture --test-threads=1 init_container_module_loading

kind-status: check-tools ## Show the persistent kind resources and resolver pods.
	$(KUBECTL) get pods,service --all-namespaces
	$(KUBECTL) get gateway,httproute,envoyproxy,envoyextensionpolicy --namespace '$(GATEWAY_NAMESPACE)'
	$(KUBECTL) get backendtrafficpolicy,securitypolicy --namespace '$(GATEWAY_NAMESPACE)' || true

kind-logs: check-tools ## Follow logs from the generated proxy and resolver.
	$(KUBECTL) logs --namespace '$(EG_NAMESPACE)' --selector '$(ENVOY_SERVICE_SELECTOR)' --all-containers --prefix --tail=100

kind-diagnostics: check-tools ## Collect redacted cluster state for CI failure analysis.
	@mkdir --parents 'target/e2e-artifacts'
	@$(KUBECTL) get nodes --output=custom-columns='NAME:.metadata.name,STATUS:.status.conditions[?(@.type=="Ready")].status,KUBELET:.status.nodeInfo.kubeletVersion' > 'target/e2e-artifacts/nodes.txt' 2>&1 || true
	@$(KUBECTL) get pods --all-namespaces --output=custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,PHASE:.status.phase,READY:.status.containerStatuses[*].ready,RESTARTS:.status.containerStatuses[*].restartCount' > 'target/e2e-artifacts/pods.txt' 2>&1 || true
	@$(KUBECTL) get gateway,httproute,envoyproxy,envoyextensionpolicy,backendtrafficpolicy,securitypolicy --namespace '$(GATEWAY_NAMESPACE)' --output=custom-columns='KIND:.kind,NAME:.metadata.name,GENERATION:.metadata.generation,OBSERVED:.status.observedGeneration' > 'target/e2e-artifacts/gateway-resources.txt' 2>&1 || true
	@$(KUBECTL) get events --all-namespaces --sort-by=.lastTimestamp --output=custom-columns='NAMESPACE:.metadata.namespace,TYPE:.type,REASON:.reason,OBJECT:.involvedObject.kind/.involvedObject.name' > 'target/e2e-artifacts/events.txt' 2>&1 || true
	@$(KUBECTL) get deployment --all-namespaces --output=custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.readyReplicas,AVAILABLE:.status.availableReplicas,UPDATED:.status.updatedReplicas' > 'target/e2e-artifacts/deployments.txt' 2>&1 || true
	@printf '%s\n' 'Only selected resource status fields are collected. Secrets, kubeconfig data, and container logs are excluded.' > 'target/e2e-artifacts/README.txt'

kind-forward: kind-apply ## Keep a local port forward open for manual requests.
	$(MAKE) port-forward

port-forward: check-tools ## Forward the generated Envoy Service to localhost; stop with Ctrl-C.
	@service="$$($(KUBECTL) get service --namespace '$(EG_NAMESPACE)' --selector '$(ENVOY_SERVICE_SELECTOR)' --output jsonpath='{.items[0].metadata.name}')"; \
		test -n "$$service" || { echo "generated Envoy Service not found; run make up first" >&2; exit 1; }; \
		echo "forwarding $$service to http://127.0.0.1:$(PORT_FORWARD_PORT)"; \
		$(KUBECTL) port-forward --namespace '$(EG_NAMESPACE)' "service/$$service" '$(PORT_FORWARD_PORT):80'

reload: load-image ## Rebuild/reload the image and restart only the generated Envoy proxy.
	$(KUBECTL) rollout restart deployment --namespace '$(EG_NAMESPACE)' \
		--selector 'gateway.envoyproxy.io/owning-gateway-name=$(GATEWAY_NAME)'
	$(KUBECTL) rollout status deployment --namespace '$(EG_NAMESPACE)' \
		--selector 'gateway.envoyproxy.io/owning-gateway-name=$(GATEWAY_NAME)' --timeout=5m

status: check-tools ## Show kind clusters and the Envoy Gateway controller status.
	kind get clusters
	$(KUBECTL) get deployment,pods --namespace '$(EG_NAMESPACE)'
	$(KUBECTL) get gateway,httproute,envoyproxy,envoyextensionpolicy,service,deployment,pods --namespace '$(GATEWAY_NAMESPACE)'

down: check-tools ## Delete the local kind cluster.
	kind delete cluster --name '$(CLUSTER_NAME)'

kind-down: down ## Delete the persistent kind cluster.
