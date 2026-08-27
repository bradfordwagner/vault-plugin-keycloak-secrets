package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// rotateAdminSecret regenerates the plugin's own admin client_secret in Keycloak
// and persists the new value, so no human holds the secret long-term. The admin
// client lives in the auth realm, so it is looked up and regenerated there
// (target realm == auth realm).
func (b *backend) rotateAdminSecret(ctx context.Context, s logical.Storage) error {
	cfg, err := getConfig(ctx, s)
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("mount is not configured")
	}

	// Target the auth realm so the admin client looks up and regenerates its OWN
	// secret where it lives.
	client, err := newKeycloakClient(cfg, cfg.AuthRealm)
	if err != nil {
		return err
	}

	token, err := client.token(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain admin token: %w", err)
	}

	internalID, err := client.getClientByClientID(ctx, token, cfg.ClientID)
	if err != nil {
		return fmt.Errorf("failed to look up admin client: %w", err)
	}

	newSecret, err := client.regenerateClientSecret(ctx, token, internalID)
	if err != nil {
		return fmt.Errorf("failed to regenerate client secret: %w", err)
	}

	cfg.ClientSecret = newSecret
	cfg.LastRotated = time.Now().Unix()
	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	// Best-effort verification: the new secret is already persisted and Keycloak
	// is the source of truth, so a verification failure must not fail the rotate.
	verifyClient, err := newKeycloakClient(cfg, cfg.AuthRealm)
	if err != nil {
		b.Logger().Warn("failed to build client to verify rotated secret", "error", err)
	} else if _, err := verifyClient.token(ctx); err != nil {
		b.Logger().Warn("rotated admin secret failed verification; Keycloak remains source of truth", "error", err)
	}

	return nil
}

// pathConfigRotate defines the config/rotate endpoint that regenerates the
// plugin's own admin client_secret in Keycloak and stores the new value. It is
// the documented break-glass trigger; automatic rotation is driven by
// periodicFunc.
func (b *backend) pathConfigRotate() *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigRotateWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigRotateWrite},
		},
		HelpSynopsis:    "Rotate the plugin's own Keycloak admin client_secret.",
		HelpDescription: "This endpoint regenerates the admin client_secret in Keycloak and stores the new value, so the secret used to bootstrap the mount need not be retained by a human. It is the break-glass trigger; automatic rotation is configured via rotation_period on the config.",
	}
}

func (b *backend) pathConfigRotateWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("mount is not configured"), nil
	}

	if err := b.rotateAdminSecret(ctx, req.Storage); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"rotated":           true,
			"client_secret_set": true,
		},
	}, nil
}
