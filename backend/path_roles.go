package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// rolesStoragePrefix returns the per-realm storage prefix under which roles are
// stored.
func rolesStoragePrefix(realm string) string {
	return "realm/" + realm + "/roles/"
}

// keycloakRole references an existing template client to clone. Reading
// realm/<realm>/creds/<name> clones the client identified by SourceClientID
// (copying its configuration and service-account role mappings), forces the
// clone to be confidential, and returns the clone's credentials.
type keycloakRole struct {
	TTL            time.Duration `json:"ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
	SourceClientID string        `json:"source_client_id"`
	RealmRoles     []string      `json:"realm_roles"` // extra realm roles granted to the clone's service account, in addition to those copied from the source client
	SyncUpstream   bool          `json:"sync_upstream"`
}

// pathRoles defines the realm/<realm>/roles/<name> endpoint.
func (b *backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: "realm/" + framework.GenericNameRegex("realm") + "/roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"realm": {
				Type:        framework.TypeString,
				Description: "Realm in which clients are created (taken from the path).",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease TTL for clients issued from this role.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum lease TTL for clients issued from this role.",
			},
			"source_client_id": {
				Type:        framework.TypeString,
				Description: "clientId of the existing template client to clone for each credential. Required.",
			},
			"realm_roles": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Extra realm roles granted to the clone's service account, in addition to those copied from the source client.",
			},
			"sync_upstream": {
				Type:        framework.TypeBool,
				Description: "When true, clones issued from this role are updated to match the source (template) client whenever the source client changes in Keycloak. Each clone's client_id and client_secret are preserved, so existing leases keep working.",
			},
		},
		ExistenceCheck: b.rolesExists,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesDelete},
		},
		HelpSynopsis:    "Manage roles for the Keycloak secrets engine.",
		HelpDescription: "This endpoint manages roles. A role references an existing template client via source_client_id; reading realm/<realm>/creds/<name> clones that client and returns the clone's credentials.",
	}
}

// pathRolesList defines the realm/<realm>/roles/ list endpoint.
func (b *backend) pathRolesList() *framework.Path {
	return &framework.Path{
		Pattern: "realm/" + framework.GenericNameRegex("realm") + "/roles/?$",
		Fields: map[string]*framework.FieldSchema{
			"realm": {
				Type:        framework.TypeString,
				Description: "Realm whose roles to list (taken from the path).",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList2},
		},
		HelpSynopsis:    "List the configured roles for a realm.",
		HelpDescription: "List the names of all configured roles in the realm named in the path.",
	}
}

func (b *backend) rolesExists(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	realm := data.Get("realm").(string)
	name := data.Get("name").(string)
	role, err := getRole(ctx, req.Storage, realm, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

// getRole loads a role by realm and name, returning nil (no error) when it does
// not exist.
func getRole(ctx context.Context, s logical.Storage, realm, name string) (*keycloakRole, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}
	entry, err := s.Get(ctx, rolesStoragePrefix(realm)+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	role := &keycloakRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

// pathRolesWrite is an idempotent upsert: create and update share this handler,
// so an external reconciler can re-PUT the same body harmlessly.
func (b *backend) pathRolesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	realm := data.Get("realm").(string)
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := getRole(ctx, req.Storage, realm, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &keycloakRole{}
	}

	if v, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("source_client_id"); ok {
		role.SourceClientID = v.(string)
	}
	if v, ok := data.GetOk("realm_roles"); ok {
		role.RealmRoles = v.([]string)
	}
	if v, ok := data.GetOk("sync_upstream"); ok {
		role.SyncUpstream = v.(bool)
	}

	if req.Operation == logical.CreateOperation && role.SourceClientID == "" {
		return logical.ErrorResponse("source_client_id is required"), nil
	}

	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	entry, err := logical.StorageEntryJSON(rolesStoragePrefix(realm)+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	realm := data.Get("realm").(string)
	name := data.Get("name").(string)
	role, err := getRole(ctx, req.Storage, realm, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"ttl":              int64(role.TTL.Seconds()),
			"max_ttl":          int64(role.MaxTTL.Seconds()),
			"source_client_id": role.SourceClientID,
			"realm_roles":      role.RealmRoles,
			"sync_upstream":    role.SyncUpstream,
		},
	}, nil
}

func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	realm := data.Get("realm").(string)
	name := data.Get("name").(string)
	if err := req.Storage.Delete(ctx, rolesStoragePrefix(realm)+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRolesList2(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	realm := data.Get("realm").(string)
	names, err := req.Storage.List(ctx, rolesStoragePrefix(realm))
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}
