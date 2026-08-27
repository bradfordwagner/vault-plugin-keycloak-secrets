# vault-plugin-keycloak-secrets

A HashiCorp Vault secrets-engine plugin that vends **dynamic Keycloak client credentials**.
On a read of `realm/<realm>/creds/<role>`, the plugin creates an ephemeral Keycloak client
(service account) in that realm and returns its `client_id` / `client_secret`. When the
Vault lease expires, the client is deleted.

A single mount serves **many realms**: one admin credential (in the `master` realm by
default) administers every realm, and realms are addressed by path.

## Paths

```
config                        one admin credential + connection (master realm by default)
config/rotate                 break-glass: rotate the admin secret now
realm/<realm>/roles           list roles defined for a realm
realm/<realm>/roles/<name>    role: client template + TTLs for a realm
realm/<realm>/creds/<name>    dynamic client_id + client_secret (leased; deleted on expiry)
realm                         list realms that have roles defined
```

Layout:

```
cmd/            -> plugin.ServeMultiplex
backend/        -> framework.Backend, Factory
  path_config.go   config       (Keycloak URL + admin auth + rotation_period)
  rotate.go        config/rotate + shared rotate helper + PeriodicFunc auto-rotation
  path_roles.go    realm/<realm>/roles
  path_creds.go    realm/<realm>/creds
  secret_client.go revoke -> delete Keycloak client on lease expiry
```

## The admin credential and its rotation

The plugin authenticates to Keycloak's Admin REST API as one **confidential
service-account client** that lives in the auth realm (`auth_realm`, default
`master`) and is granted per-realm management roles for the realms it provisions
into. Defining that client (declaratively, least-privilege) is documented in
[`docs/admin-client.md`](docs/admin-client.md).

The admin secret is **never held long-term by a human**:

- **Seed once** — write `config` with the client_secret Keycloak generated. Do
  this with an idempotent one-time step so the secret never lands in git; see
  [`deploy/`](deploy/README.md) for the deployer contract (what to write, the
  least-privilege Vault policy, and why the seed is transient).
- **Automatic rotation** — set `rotation_period` on `config`. A background
  `PeriodicFunc` regenerates the admin secret in Keycloak and stores the new
  value once the period elapses. A freshly seeded config rotates on the **first
  tick** (within ~a minute), which purges the human-seeded secret quickly.

  ```sh
  vault write keycloak/config \
    server_url=https://keycloak.example.com \
    auth_realm=master \
    client_id=vault-keycloak-secrets-admin \
    client_secret=<seed value> \
    rotation_period=720h
  ```

- **Break-glass (manual)** — force an immediate rotation at any time:

  ```sh
  vault write -f keycloak/config/rotate
  ```

  Use this if you suspect exposure, or to purge the seed secret immediately
  rather than waiting for the first automatic tick.

`config` reads never return the secret — only `client_secret_set`, plus
`rotation_period` and `last_rotated` so you can confirm rotation is happening.

## Build

```sh
go build ./cmd/vault-plugin-keycloak-secrets
```

Release-style artifacts (no publish) via GoReleaser:

```sh
goreleaser release --snapshot --clean   # or: task release:snapshot
```

## Local development

Two loops deliver the plugin:

- **Inner loop** (`task dev:push`): the fast path. It cross-compiles the binary
  and copies it straight onto the `vault-0` pod, then registers + reloads it in
  place. This **bypasses the in-cluster plugin manager** entirely — it is
  dev-only.
- **Integration/production**: a tagged GoReleaser release (see below), whose
  asset the in-cluster plugin manager fetches by URL.

`KUBECONFIG` and `CONTEXT` are **mandatory** on every dev task — explicit
kubeconfig + context is repo policy, so we never touch ambient kube config:

```sh
task dev:push KUBECONFIG=/path/to/kubeconfig CONTEXT=my-context
```

One-time, enable the secrets engine mount at `keycloak`:

```sh
task dev:enable KUBECONFIG=/path/to/kubeconfig CONTEXT=my-context
```

(amd64/WSL2 devs: add `ARCH=amd64`.)

## Release

Pushing a tag triggers **two independent, parallel delivery paths** (separate
workflows, both firing on the tag):

1. **GitHub release archives** (`.github/workflows/goreleaser.yml`) — GoReleaser
   publishes per-OS/arch `tar.gz` archives plus a `checksums.txt`. Each archive
   is **binary-only** (no README/LICENSE inside).
2. **OCI carrier image** (`.github/workflows/docker_tags.yml`) — a multi-arch
   `scratch` image at `ghcr.io/bradfordwagner/vault-plugin-keycloak-secrets`,
   tagged `:<tag>` and `:<tag>-scratch`, carrying the binary at
   `/usr/local/bin/vault-plugin-keycloak-secrets`. The image is a **carrier**,
   not a runnable service — it exists so the plugin manager can extract the
   binary. (Branch pushes build the image on both arches without pushing, via
   `docker_branches.yml`.)

### Consuming from the plugin manager (vpm)

The [`vault-plugin-manager`](https://github.com/bradfordwagner/vault-plugin-manager)
`catalog[].source` accepts either path. Pick one:

```yaml
# (1) GitHub release archive — over HTTPS.
source:
  url: https://github.com/bradfordwagner/vault-plugin-keycloak-secrets/releases/download/v1.2.3/vault-plugin-keycloak-secrets_1.2.3_linux_amd64.tar.gz
  # `binary:` is NOT needed — the archive holds exactly one file, so the fetcher
  # selects it unambiguously.

# (2) OCI carrier image.
source:
  image: ghcr.io/bradfordwagner/vault-plugin-keycloak-secrets:v1.2.3-scratch
  path:  /usr/local/bin/vault-plugin-keycloak-secrets
```

Two sha256 gotchas, both because vpm verifies the checksum of the **extracted
binary**, not of the archive:

- The GitHub release tag is `vX.Y.Z`, but the archive filename embeds the
  version **without** the leading `v` (`…_1.2.3_linux_amd64.tar.gz`). Match the
  URL exactly.
- The `checksums.txt` in the release covers the **archives**. If you pin
  `source.sha256`, it must be the checksum of the binary *inside* the archive,
  which differs from the archive checksum. Compute it with:

  ```sh
  curl -sL <archive-url> | tar -xzO | sha256sum
  ```

  Leaving `source.sha256` unset is fine — HTTPS plus the immutable release asset
  protect the download, and vpm re-verifies the binary's sha on every Vault pod
  after copy regardless.
