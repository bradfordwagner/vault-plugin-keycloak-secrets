# syntax=docker/dockerfile:1

# This image is a BINARY CARRIER, not a runnable service. The plugin is a Vault
# secrets engine: Vault execs it on the Vault pod over the plugin gRPC
# transport. The in-cluster plugin manager (vault-plugin-manager) consumes this
# image via its OCI source — it extracts the binary from the image rootfs at
# BINARY_PATH below and copies it onto every Vault pod's plugin_directory,
# verifying the sha256 before registering it. The GoReleaser GitHub release is
# the parallel delivery path (per-OS/arch tar.gz via vpm's `url:` source); this
# image is the `image:`/`path:` source.
#
#   vpm catalog[].source:
#     image: ghcr.io/bradfordwagner/vault-plugin-keycloak-secrets:<tag>-scratch
#     path:  /usr/local/bin/vault-plugin-keycloak-secrets

# Build with the owned Go builder (override BUILDER_IMAGE in CI to pin a tag).
ARG BUILDER_IMAGE=ghcr.io/bradfordwagner/go-builder:1.26-ubuntu_noble
# Final base. scratch keeps the carrier minimal; the binary is never run here.
ARG BASE_IMAGE=scratch

# --- build stage -----------------------------------------------------------
FROM ${BUILDER_IMAGE} AS build
WORKDIR /src
# CGO off for a static binary; GOTOOLCHAIN=auto fetches the go.mod toolchain if
# the builder ships a different minor.
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto
# Version metadata, set by CI to the release tag / commit. Matches the ldflags
# GoReleaser injects, so an image-delivered binary self-reports the same version.
ARG VERSION=dev
ARG COMMIT=none
COPY . .
RUN go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/vault-plugin-keycloak-secrets ./cmd/vault-plugin-keycloak-secrets

# --- final image (carrier) -------------------------------------------------
FROM ${BASE_IMAGE}
COPY --from=build /out/vault-plugin-keycloak-secrets /usr/local/bin/vault-plugin-keycloak-secrets
# Running the container standalone just starts the plugin gRPC server, which is
# only meaningful when Vault execs it; the intended use is binary extraction.
ENTRYPOINT ["/usr/local/bin/vault-plugin-keycloak-secrets"]
