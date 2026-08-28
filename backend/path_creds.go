package backend

import (
	"context"
	"fmt"
	"time"

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
		HelpDescription: "This endpoint clones the template client referenced by the named role's source_client_id (copying its configuration and service-account role mappings), forces the clone to be a confidential client, and returns its client_id and client_secret. The clone is deleted when the lease expires or is revoked.",
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
	if role.SourceClientID == "" {
		return logical.ErrorResponse("role %q has no source_client_id", name), nil
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

	// Resolve the source template client and fetch its full representation.
	sourceInternalID, err := client.getClientByClientID(ctx, token, role.SourceClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up source client %q: %w", role.SourceClientID, err)
	}
	srcRaw, err := client.getClientRaw(ctx, token, sourceInternalID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch source client %q: %w", role.SourceClientID, err)
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	cloneClientID := role.SourceClientID + "-vkp-" + id

	cloneRaw := buildCloneRepresentation(srcRaw, cloneClientID)

	// Stamp trace metadata onto the clone: provenance (vkp + template), timing
	// (created + max expiry), and the creds path that issued it. The owning lease
	// id is intentionally not recorded — Vault never hands a backend its own lease
	// id — so a clone is traced back to its lease out-of-band via the creds path.
	applyTracking(cloneRaw, trackingInfo{
		SourceClientID: role.SourceClientID,
		Mount:          req.MountPoint,
		Realm:          realm,
		Role:           name,
		CredsPath:      req.MountPoint + "realm/" + realm + "/creds/" + name,
		Created:        time.Now(),
		TTL:            role.TTL,
		MaxTTL:         role.MaxTTL,
	})

	cloneInternalID, err := client.createClientRaw(ctx, token, cloneRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to create keycloak client clone: %w", err)
	}

	// From here on, any failure must clean up the created clone to avoid orphans.
	fail := func(err error) (*logical.Response, error) {
		if delErr := client.deleteClient(ctx, token, cloneInternalID); delErr != nil {
			b.Logger().Warn("failed to clean up orphaned keycloak client after error",
				"client_id", cloneClientID, "internal_id", cloneInternalID, "error", delErr)
		}
		return nil, err
	}

	// Record the clone so the upstream-sync pass can find and update it while the
	// lease is live (deleted again by the lease's revoke).
	if err := writeCloneRecord(ctx, req.Storage, realm, name, cloneRecord{
		CloneClientID: cloneClientID,
		InternalID:    cloneInternalID,
	}); err != nil {
		return fail(fmt.Errorf("failed to record clone for upstream sync: %w", err))
	}

	// A clone copies serviceAccountsEnabled from the source; only when the source
	// has a service account does the clone have one whose role mappings we can
	// populate.
	srcHasServiceAccount, _ := srcRaw["serviceAccountsEnabled"].(bool)

	if srcHasServiceAccount {
		srcSA, err := client.serviceAccountUserID(ctx, token, sourceInternalID)
		if err != nil {
			return fail(fmt.Errorf("failed to get source service account user: %w", err))
		}
		cloneSA, err := client.serviceAccountUserID(ctx, token, cloneInternalID)
		if err != nil {
			return fail(fmt.Errorf("failed to get clone service account user: %w", err))
		}

		// Copy the source service account's role mappings onto the clone's.
		mappings, err := client.userRoleMappings(ctx, token, srcSA)
		if err != nil {
			return fail(fmt.Errorf("failed to read source service account role mappings: %w", err))
		}
		if len(mappings.RealmMappings) > 0 {
			if err := client.assignRealmRoles(ctx, token, cloneSA, mappings.RealmMappings); err != nil {
				return fail(fmt.Errorf("failed to copy realm role mappings: %w", err))
			}
		}
		// Client role definitions live on their owning (unchanged) client, so the
		// target internal id is the same for source and clone.
		for _, entry := range mappings.ClientMappings {
			if len(entry.Mappings) == 0 {
				continue
			}
			if err := client.assignClientRoles(ctx, token, cloneSA, entry.ID, entry.Mappings); err != nil {
				return fail(fmt.Errorf("failed to copy client role mappings for %q: %w", entry.Client, err))
			}
		}

		// Additive extra realm roles from the role definition.
		if len(role.RealmRoles) > 0 {
			var resolved []roleRepresentation
			for _, rn := range role.RealmRoles {
				rr, err := client.realmRole(ctx, token, rn)
				if err != nil {
					return fail(fmt.Errorf("failed to resolve realm role %q: %w", rn, err))
				}
				resolved = append(resolved, *rr)
			}
			if err := client.assignRealmRoles(ctx, token, cloneSA, resolved); err != nil {
				return fail(fmt.Errorf("failed to assign extra realm roles: %w", err))
			}
		}
	}

	clientSecret, err := client.getClientSecret(ctx, token, cloneInternalID)
	if err != nil {
		return fail(fmt.Errorf("failed to get client secret: %w", err))
	}

	respData := map[string]interface{}{
		"client_id":     cloneClientID,
		"client_secret": clientSecret,
		"realm":         realm,
	}
	internal := map[string]interface{}{
		"internal_id": cloneInternalID,
		"realm":       realm,
		"role":        name,
	}

	resp := b.Secret(secretClientType).Response(respData, internal)
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}
