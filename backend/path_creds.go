package backend

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCreds defines the realm/<realm>/creds/<name> endpoint that mints an
// ephemeral client.
func (b *backend) pathCreds() *framework.Path {
	return &framework.Path{
		Pattern: "realm/" + framework.GenericNameRegex("realm") + "/creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"realm": {
				Type:        framework.TypeString,
				Description: "Realm in which to create the client (taken from the path).",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role to generate credentials against.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredsRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredsRead},
		},
		HelpSynopsis:    "Generate an ephemeral Keycloak client for a role.",
		HelpDescription: "This endpoint creates a new Keycloak client from the named role's template and returns its client_id and client_secret. The client is deleted when the lease expires or is revoked.",
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	realm := data.Get("realm").(string)
	name := data.Get("name").(string)

	role, err := getRole(ctx, req.Storage, realm, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", name), nil
	}

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("mount is not configured; write config first"), nil
	}

	client, err := newKeycloakClient(cfg, realm)
	if err != nil {
		return nil, err
	}

	token, err := client.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain admin token: %w", err)
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	prefix := role.ClientIDPrefix
	if prefix == "" {
		prefix = fmt.Sprintf("vault-%s-", name)
	}
	clientID := prefix + id

	cr := &clientRepresentation{
		ClientID:                  clientID,
		Protocol:                  "openid-connect",
		PublicClient:              role.PublicClient,
		ServiceAccountsEnabled:    role.ServiceAccountsEnabled,
		StandardFlowEnabled:       role.StandardFlowEnabled,
		DirectAccessGrantsEnabled: role.DirectAccessGrantsEnabled,
		Enabled:                   true,
		DefaultClientScopes:       role.DefaultClientScopes,
		OptionalClientScopes:      role.OptionalClientScopes,
		RedirectUris:              role.RedirectURIs,
	}

	internalID, err := client.createClient(ctx, token, cr)
	if err != nil {
		return nil, fmt.Errorf("failed to create keycloak client: %w", err)
	}

	// From here on, any failure must clean up the created client to avoid orphans.
	fail := func(err error) (*logical.Response, error) {
		if delErr := client.deleteClient(ctx, token, internalID); delErr != nil {
			b.Logger().Warn("failed to clean up orphaned keycloak client after error",
				"client_id", clientID, "internal_id", internalID, "error", delErr)
		}
		return nil, err
	}

	if role.ServiceAccountsEnabled && len(role.RealmRoles) > 0 {
		var resolved []roleRepresentation
		for _, rn := range role.RealmRoles {
			rr, err := client.realmRole(ctx, token, rn)
			if err != nil {
				return fail(fmt.Errorf("failed to resolve realm role %q: %w", rn, err))
			}
			resolved = append(resolved, *rr)
		}
		if len(resolved) > 0 {
			saUserID, err := client.serviceAccountUserID(ctx, token, internalID)
			if err != nil {
				return fail(fmt.Errorf("failed to get service account user: %w", err))
			}
			if err := client.assignRealmRoles(ctx, token, saUserID, resolved); err != nil {
				return fail(fmt.Errorf("failed to assign realm roles: %w", err))
			}
		}
	}

	var clientSecret string
	if !role.PublicClient {
		clientSecret, err = client.getClientSecret(ctx, token, internalID)
		if err != nil {
			return fail(fmt.Errorf("failed to get client secret: %w", err))
		}
	}

	respData := map[string]interface{}{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"realm":         realm,
	}
	internal := map[string]interface{}{
		"internal_id": internalID,
		"realm":       realm,
		"role":        name,
	}

	resp := b.Secret(secretClientType).Response(respData, internal)
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}
