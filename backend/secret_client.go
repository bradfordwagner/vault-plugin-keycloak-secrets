package backend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// secretClientType is the Vault secret type for issued Keycloak clients.
const secretClientType = "client"

// secretClient describes the lifecycle of an issued Keycloak client lease.
func (b *backend) secretClient() *framework.Secret {
	return &framework.Secret{
		Type: secretClientType,
		Fields: map[string]*framework.FieldSchema{
			"client_id": {
				Type:        framework.TypeString,
				Description: "The client ID of the issued Keycloak client.",
			},
			"client_secret": {
				Type:        framework.TypeString,
				Description: "The client secret of the issued Keycloak client.",
			},
		},
		Revoke: b.secretClientRevoke,
		Renew:  b.secretClientRenew,
	}
}

func (b *backend) secretClientRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	internalIDRaw, ok := req.Secret.InternalData["internal_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing internal_id internal data")
	}
	internalID, ok := internalIDRaw.(string)
	if !ok {
		return nil, fmt.Errorf("internal_id has unexpected type %T", internalIDRaw)
	}

	realm, ok := req.Secret.InternalData["realm"].(string)
	if !ok || realm == "" {
		return nil, fmt.Errorf("secret is missing realm internal data")
	}

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("mount is not configured; cannot revoke client")
	}

	client, err := newKeycloakClient(cfg, realm)
	if err != nil {
		return nil, err
	}
	token, err := client.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain admin token: %w", err)
	}

	if err := client.deleteClient(ctx, token, internalID); err != nil {
		return nil, fmt.Errorf("failed to delete keycloak client: %w", err)
	}

	// Best-effort: drop this clone from the upstream-sync index. The Keycloak
	// client is already gone, so a stale index entry is harmless; log and move on.
	if roleName, ok := req.Secret.InternalData["role"].(string); ok && roleName != "" {
		if err := deleteCloneRecord(ctx, req.Storage, realm, roleName, internalID); err != nil {
			b.Logger().Warn("failed to delete clone index record on revoke",
				"realm", realm, "role", roleName, "internal_id", internalID, "error", err)
		}
	}
	return nil, nil
}

func (b *backend) secretClientRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}

	// Default to the lease's existing durations in case the role is gone.
	ttl := req.Secret.TTL
	maxTTL := req.Secret.MaxTTL

	roleName, _ := req.Secret.InternalData["role"].(string)
	realm, _ := req.Secret.InternalData["realm"].(string)
	if roleName != "" && realm != "" {
		role, err := getRole(ctx, req.Storage, realm, roleName)
		if err != nil {
			return nil, err
		}
		if role != nil {
			ttl = role.TTL
			maxTTL = role.MaxTTL
		}
	}

	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL
	return resp, nil
}
