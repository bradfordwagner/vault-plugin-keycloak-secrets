package backend

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend is the Keycloak dynamic-client secrets engine.
type backend struct {
	*framework.Backend
}

// Factory returns a set-up Keycloak secrets backend. Referenced from
// cmd/vault-plugin-keycloak-secrets/main.go via plugin.ServeMultiplex.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() *backend {
	b := &backend{}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// Only the mount-level config holds a secret (the master-global admin
			// client_secret), so seal-wrap just that key.
			SealWrapStorage: []string{configStoragePath},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathConfig(),
				b.pathConfigRotate(),
				b.pathRealmsList(),
				b.pathRolesList(),
				b.pathRoles(),
				b.pathCreds(),
			},
		),
		Secrets: []*framework.Secret{
			b.secretClient(),
		},
		PeriodicFunc: b.periodicFunc,
	}
	return b
}

// periodicFunc drives automatic self-rotation of the admin secret. Vault calls
// it on its periodic schedule; it rotates when the configured rotation_period
// has elapsed since the last rotation.
func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return err
	}
	// Nothing to do until the admin connection is fully configured.
	if !cfg.isConfigured() {
		return nil
	}

	// Automatic admin-secret rotation, only when a positive period is set. A
	// freshly seeded config has LastRotated == 0, so the first periodic tick
	// rotates immediately. This is intended: it purges the human-seeded secret
	// as soon as possible.
	if cfg.RotationPeriod > 0 && time.Now().Unix()-cfg.LastRotated >= cfg.RotationPeriod {
		if err := b.rotateAdminSecret(ctx, req.Storage); err != nil {
			// Do not return the error: Vault treats periodic failures as fatal/noisy,
			// and Keycloak remains the source of truth. Warn and move on.
			b.Logger().Warn("automatic admin secret rotation failed", "error", err)
		} else {
			b.Logger().Info("rotated admin secret", "next_after_seconds", cfg.RotationPeriod)
		}
	}

	// Propagate source (template) client changes onto live clones for roles that
	// opt in via sync_upstream. Best-effort: Keycloak is the source of truth, so a
	// sync failure must never make the periodic tick fail.
	if err := b.syncUpstream(ctx, req.Storage); err != nil {
		b.Logger().Warn("upstream clone sync failed", "error", err)
	}
	return nil
}

// pathRealmsList defines the realm/ list endpoint that enumerates realms with at
// least one role defined. Config is mount-level now, so this reflects roles, not
// configured realms.
func (b *backend) pathRealmsList() *framework.Path {
	return &framework.Path{
		Pattern: "realm/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRealmsListRead},
		},
		HelpSynopsis:    "List realms that have roles defined.",
		HelpDescription: "List the names of realms that have at least one role stored under this mount.",
	}
}

func (b *backend) pathRealmsListRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "realm/")
	if err != nil {
		return nil, err
	}
	realms := make([]string, 0, len(entries))
	for _, e := range entries {
		realms = append(realms, strings.TrimSuffix(e, "/"))
	}
	return logical.ListResponse(realms), nil
}

const backendHelp = `
The Keycloak secrets engine dynamically provisions ephemeral Keycloak OIDC
clients on demand. A single mount serves multiple Keycloak realms; the realm is
carried in the request path as realm/<realm>/... .

Configure the connection and a single master-global admin credential at the
mount-level config endpoint. The admin client lives in the auth realm (default
master) and administers every other realm. Set rotation_period on the config to
have the plugin automatically self-rotate its own admin client_secret on a
schedule; the config/rotate endpoint remains a manual break-glass trigger.

Define one or more roles at realm/<realm>/roles/<name>. A role references an
existing template client in <realm> via source_client_id. Each read of
realm/<realm>/creds/<name> CLONES that template client (copying its
configuration and its service-account role mappings), forces the clone to be a
confidential client, names it <source_client_id>-vkp-<uuid>, and returns the
clone's client_id and client_secret. When the Vault lease expires or is revoked,
the clone is deleted from Keycloak.

Set sync_upstream=true on a role to keep its live clones tracking the source
client: a background pass detects when the source client changes in Keycloak and
updates every outstanding clone to match, preserving each clone's client_id and
client_secret so existing leases keep working.

List realms that have roles defined at realm/ and a realm's roles at
realm/<realm>/roles/.
`
