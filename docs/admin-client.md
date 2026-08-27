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

| role            | why the engine needs it                                        |
| --------------- | -------------------------------------------------------------- |
| `manage-clients`| create / read client-secret / delete the dynamic clients      |
| `manage-users`  | read the client's service-account user, map realm roles to it |
| `view-realm`    | resolve realm roles by name before mapping them               |

Grant these per managed realm. Do **not** grant the master `admin` composite role
(it can do everything in every realm) unless you deliberately accept that blast
radius — enumerating `<realm>-realm` roles keeps the credential scoped to only the
realms you provision into.

> Note: when the engine rotates its **own** secret, it operates on this client
> inside the auth realm, so the service account implicitly needs to manage clients
> in the auth realm too. If the auth realm is `master`, include a `realm-management`
> `manage-clients` grant for master; if you provision into `master` as well, the
> `realm-management` block below already covers it.

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
