# The admin client this engine authenticates as

This secrets engine authenticates to Keycloak's Admin REST API as **one
confidential service-account client** that lives in the **auth realm**
(`auth_realm` in `config`, default `master`). Because the `master` realm can
administer every other realm, this single credential provisions dynamic clients
across all realms the mount serves — realms are addressed by path
(`<mount>/realm/<realm>/...`), not by separate credentials.

The client is declarative topology — define it in your realm import
(e.g. [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli)) in
the auth realm. Its **secret is not** declared: Keycloak generates it, the engine
reads it once at seed time, and thereafter the engine rotates it itself (see
"Rotation" below). Never pin a secret in the import file — a config re-apply would
clobber a rotated secret.

## Least privilege across realms

A `master`-realm service account manages another realm `<realm>` through that
realm's built-in management client, named `<realm>-realm` (these clients live in
`master`, one per realm). The engine needs exactly three fine-grained roles from
each managed realm's `<realm>-realm` client:

| role            | why the engine needs it                                                          |
| --------------- | ------------------------------------------------------------------------------- |
| `manage-clients`| read the template client's full representation, create / read client-secret / update / delete the cloned clients |
| `manage-users`  | read the template client's service-account role mappings, map realm + client roles onto the clone's service account |
| `view-realm`    | resolve extra realm roles by name before mapping them                            |

Because `creds` reads now **clone an existing template client** (`source_client_id`),
the engine additionally reads that template client's representation and its
service-account role mappings and copies both (realm-role and client-role mappings)
onto each clone's service account. When a role sets `sync_upstream=true`, the
background sync pass additionally issues client **UPDATEs** (`PUT`) against each
live clone to re-apply the template's configuration and re-copy its
service-account role mappings. All of this stays within the same three per-realm
roles above — no extra grants are required.

Grant these per managed realm. Do **not** grant the master `admin` composite role
(it can do everything in every realm) unless you deliberately accept that blast
radius — enumerating `<realm>-realm` roles keeps the credential scoped to only the
realms you provision into.

> Note: when the engine rotates its **own** secret, it operates on this client
> inside the auth realm, so the service account implicitly needs to manage clients
> in the auth realm too. If the auth realm is `master`, include a `realm-management`
> `manage-clients` grant for master; if you provision into `master` as well, the
> `realm-management` block below already covers it.

## Admin API audience (Keycloak 26.8.2+)

Keycloak 26.8.2 rejects Admin REST API tokens that lack the admin API audience,
answering `401 Unauthorized` even when the service account holds every role
above. The audience comes from the built-in `kc-admin-api` client scope, which
Keycloak assigns to its own `admin-cli` but **not** to clients you create. Add it
to the admin client's default client scopes. Without it the engine fails every
creds read and rotation with:

```
keycloak admin API rejected the token: status 401: ... (Keycloak 26.8.2+ requires the kc-admin-api client scope ...)
```

The scope does not exist before 26.8.2; assign it once the server is on 26.8.2 or
later.

**Upgrading an existing Keycloak breaks a working engine.** The 26.8.2 migration
creates `kc-admin-api` in every realm but assigns it only to `admin-cli` and
`security-admin-console`, so an admin client set up on an earlier version starts
getting 401 the moment the server is upgraded, with no plugin change. Assign the
scope right after upgrading (or as part of the same rollout). This applies
whichever realm is the `auth_realm`: the scope exists in every realm, and the
audience it adds names the realm that minted the token.

## keycloak-config-cli snippet (define in the auth realm, e.g. `master`)

```yaml
# realm: master                      # the auth realm
clients:
  - clientId: vault-keycloak-secrets-admin
    name: "Vault Keycloak secrets engine admin"
    description: "Service account the Vault Keycloak secrets engine uses to provision dynamic clients."
    enabled: true
    protocol: openid-connect
    publicClient: false            # confidential
    serviceAccountsEnabled: true   # client_credentials grant
    standardFlowEnabled: false     # no browser/auth-code flow
    implicitFlowEnabled: false
    directAccessGrantsEnabled: false
    # Keycloak 26.8.2+: kc-admin-api carries the admin API audience. This list
    # replaces the client's defaults, so restate the ones you keep.
    defaultClientScopes:
      - acr
      - basic
      - email
      - profile
      - roles
      - service_account
      - web-origins
      - kc-admin-api
    # NOTE: no `secret:` here on purpose. Keycloak generates it; the seed job
    # reads it once into Vault, then the engine rotates it.

users:
  # keycloak-config-cli manages a client's service account as this special user.
  - username: service-account-vault-keycloak-secrets-admin
    enabled: true
    serviceAccountClientId: vault-keycloak-secrets-admin
    clientRoles:
      # One block per realm this mount provisions into. `<realm>-realm` is the
      # management client that exists in master for the realm named "<realm>".
      example-realm:
        - manage-clients
        - manage-users
        - view-realm
      # another-realm:
      #   - manage-clients
      #   - manage-users
      #   - view-realm
      # Include realm-management too if you also provision into master itself:
      # realm-management:
      #   - manage-clients
      #   - manage-users
      #   - view-realm
```

## After import: hand the secret to Vault once, then let it rotate

1. keycloak-config-cli creates the client with a Keycloak-generated secret.
2. Read that secret out of Keycloak (admin console → realm `master` → Clients →
   `vault-keycloak-secrets-admin` → Credentials, or the Admin REST API) and put
   it in the Kubernetes Secret the seed job consumes — see
   [`../deploy/README.md`](../deploy/README.md). It never goes in git.
3. The seed job writes `<mount>/config` (idempotently) including
   `rotation_period`.
4. **Rotation is automatic.** With `rotation_period` set, the engine regenerates
   this secret in Keycloak and stores the new value once the period elapses; a
   freshly seeded config rotates on the first tick (within ~a minute), purging
   the human-seeded secret. To force it immediately (break-glass):

   ```bash
   vault write -f <mount>/config/rotate
   ```

   From here Keycloak is the source of truth for the secret and Vault holds the
   only live copy. Re-running the seed job is safe: it detects the configured
   mount and exits 0 without overwriting the rotated secret.
