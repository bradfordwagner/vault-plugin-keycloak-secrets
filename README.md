# vault-plugin-keycloak-secrets

A HashiCorp Vault secrets-engine plugin that vends **dynamic Keycloak client credentials**.
On a read of `creds/<role>`, the plugin creates an ephemeral Keycloak client (service
account) and returns its `client_id` / `client_secret`. When the Vault lease expires, the
client is deleted.

> Status: scaffolding. The plugin is not yet implemented.

## Planned layout

```
main.go / cmd/  -> plugin.ServeMultiplex
backend/        -> framework.Backend, Factory
  path_config.go   config/  (Keycloak URL + admin auth)
  path_roles.go    roles/   (target realm, TTLs)
  path_creds.go    creds/   (dynamic client_id + client_secret)
  secret_client.go revoke -> delete Keycloak client on lease expiry
```

## Build

Go binary, released via GoReleaser (matches the sibling `vault-jwt-auth` house style).
