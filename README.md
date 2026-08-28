# vault-plugin-keycloak-secrets

A HashiCorp Vault secrets-engine plugin that vends **dynamic Keycloak client credentials**.
A role points at an existing **template client** via `source_client_id`. On a read of
`realm/<realm>/creds/<role>`, the plugin **clones that template client** — copying its
configuration and its service-account role mappings — into a new ephemeral client named
`<source_client_id>-vkp-<uuid>`, **forces the clone to be confidential**, and returns its
`client_id` / `client_secret`. When the Vault lease expires, the clone is deleted.

Cloning (rather than minting from a stored template) keeps every lease backed by its own
independently-revocable client, while inheriting the real client's flows, protocol mappers,
scopes, and service-account authorization — a plain confidential client cannot hold multiple
concurrent secrets, so per-lease clients are required for independent revocation.

Set **`sync_upstream=true`** on a role to keep its live clones tracking the template. A
background pass (the plugin's `PeriodicFunc`) detects when the template client changes in
Keycloak — by hashing its representation — and re-applies the template's configuration and
service-account role mappings onto every outstanding `<source_client_id>-vkp-<uuid>` clone.
Each clone's `client_id` and `client_secret` are **preserved** across the update, so existing
leases keep working.

Deliberate limitations of upstream sync:

- **Removals are not propagated.** Service-account role mappings are re-copied *additively*, so
  new upstream grants appear on the clones but roles/mappers *removed* upstream are not diffed
  back out.
- **Subresources may not fully sync.** Protocol-mapper and client-scope edits are Keycloak
  subresources and may not propagate through a whole-client `PUT`.
- **Plain config fields do sync** — attributes, flags, `redirectUris`, `webOrigins`, and the
  like are carried in the client representation and are re-applied.
- **Best-effort per tick.** A clone whose `PUT` transiently fails stays stale until the next
  time the source client changes (the source hash is recorded after the pass regardless).

Every clone is **traceable**. Its Keycloak `description` is a bounded summary — that it
is managed by vkp, the template it clones, its owning Vault role, and when it was created
and expires — kept within Keycloak's 255-character `description` column, while the full set
of facts (created timestamp, max expiry, template, realm, role, mount, creds path) is
written as machine-readable `vkp.*` client **attributes** (`vkp.managed`,
`vkp.source_client_id`, `vkp.created`, `vkp.max_expiry`, `vkp.creds_path`, …). There is
deliberately **no `vkp.lease_id`**: Vault never hands a backend its own lease id (the SDK's
`logical.Secret.LeaseID` is always blank on a request), so the plugin cannot record the
lease that owns a clone — instead a clone is traced back to its lease out-of-band via
`vkp.creds_path`. Upstream sync preserves this metadata — a sync re-applies the template's
config but never clobbers a clone's `vkp.*` attributes or tracking description.

A single mount serves **many realms**: one admin credential (in the `master` realm by
default) administers every realm, and realms are addressed by path.

## Paths

```
config                        one admin credential + connection (master realm by default)
config/rotate                 break-glass: rotate the admin secret now
realm/<realm>/roles           list roles defined for a realm
realm/<realm>/roles/<name>    role: source_client_id (template to clone) + TTLs for a realm
realm/<realm>/creds/<name>    dynamic client_id + client_secret (leased; deleted on expiry)
realm                         list realms that have roles defined
```

Layout:

```
cmd/            -> plugin.ServeMultiplex
backend/        -> framework.Backend, Factory, PeriodicFunc (admin-secret auto-rotation + upstream sync)
  path_config.go   config       (Keycloak URL + admin auth + rotation_period)
  rotate.go        config/rotate + shared admin-secret rotate helper
  path_roles.go    realm/<realm>/roles     (source_client_id + realm_roles + sync_upstream + TTLs)
  path_creds.go    realm/<realm>/creds     (clone source client -> forced-confidential ephemeral client)
  sync.go          upstream sync: re-apply template changes onto live clones (clone index + source-hash state)
  secret_client.go revoke -> delete the cloned Keycloak client + drop its sync-index entry
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
