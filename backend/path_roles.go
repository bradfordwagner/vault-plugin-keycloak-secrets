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

// keycloakRole is a client template. Reading realm/<realm>/creds/<name> mints a
// new Keycloak client from these settings.
type keycloakRole struct {
	TTL                       time.Duration `json:"ttl"`
	MaxTTL                    time.Duration `json:"max_ttl"`
	ClientIDPrefix            string        `json:"client_id_prefix"`
	ServiceAccountsEnabled    bool          `json:"service_accounts_enabled"`
	StandardFlowEnabled       bool          `json:"standard_flow_enabled"`
	DirectAccessGrantsEnabled bool          `json:"direct_access_grants_enabled"`
	PublicClient              bool          `json:"public_client"`
	RedirectURIs              []string      `json:"redirect_uris"`
	DefaultClientScopes       []string      `json:"default_client_scopes"`
	OptionalClientScopes      []string      `json:"optional_client_scopes"`
	RealmRoles                []string      `json:"realm_roles"`
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
			"client_id_prefix": {
				Type:        framework.TypeString,
				Description: "Prefix for generated client IDs. Defaults to vault-<role>-.",
			},
			"service_accounts_enabled": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Enable the client's service account.",
			},
			"standard_flow_enabled": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Enable the standard (authorization code) flow.",
			},
			"direct_access_grants_enabled": {
				Type:        framework.TypeBool,
				Description: "Enable direct access grants (resource owner password flow).",
			},
			"public_client": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Create a public (non-confidential) client. Public clients have no secret.",
			},
			"redirect_uris": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Valid redirect URIs for the client.",
			},
			"default_client_scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Default client scopes to assign.",
			},
			"optional_client_scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Optional client scopes to assign.",
			},
			"realm_roles": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Realm roles to grant to the client's service account.",
			},
		},
		ExistenceCheck: b.rolesExists,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesDelete},
		},
		HelpSynopsis:    "Manage roles (client templates) for the Keycloak secrets engine.",
		HelpDescription: "This endpoint manages roles. A role is a template describing the Keycloak client that will be created when reading realm/<realm>/creds/<name>.",
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
	if v, ok := data.GetOk("client_id_prefix"); ok {
		role.ClientIDPrefix = v.(string)
	}
	if v, ok := data.GetOk("service_accounts_enabled"); ok {
		role.ServiceAccountsEnabled = v.(bool)
	} else if req.Operation == logical.CreateOperation {
		role.ServiceAccountsEnabled = data.Get("service_accounts_enabled").(bool)
	}
	if v, ok := data.GetOk("standard_flow_enabled"); ok {
		role.StandardFlowEnabled = v.(bool)
	} else if req.Operation == logical.CreateOperation {
		role.StandardFlowEnabled = data.Get("standard_flow_enabled").(bool)
	}
	if v, ok := data.GetOk("direct_access_grants_enabled"); ok {
		role.DirectAccessGrantsEnabled = v.(bool)
	}
	if v, ok := data.GetOk("public_client"); ok {
		role.PublicClient = v.(bool)
	} else if req.Operation == logical.CreateOperation {
		role.PublicClient = data.Get("public_client").(bool)
	}
	if v, ok := data.GetOk("redirect_uris"); ok {
		role.RedirectURIs = v.([]string)
	}
	if v, ok := data.GetOk("default_client_scopes"); ok {
		role.DefaultClientScopes = v.([]string)
	}
	if v, ok := data.GetOk("optional_client_scopes"); ok {
		role.OptionalClientScopes = v.([]string)
	}
	if v, ok := data.GetOk("realm_roles"); ok {
		role.RealmRoles = v.([]string)
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
			"ttl":                          int64(role.TTL.Seconds()),
			"max_ttl":                      int64(role.MaxTTL.Seconds()),
			"client_id_prefix":             role.ClientIDPrefix,
			"service_accounts_enabled":     role.ServiceAccountsEnabled,
			"standard_flow_enabled":        role.StandardFlowEnabled,
			"direct_access_grants_enabled": role.DirectAccessGrantsEnabled,
			"public_client":                role.PublicClient,
			"redirect_uris":                role.RedirectURIs,
			"default_client_scopes":        role.DefaultClientScopes,
			"optional_client_scopes":       role.OptionalClientScopes,
			"realm_roles":                  role.RealmRoles,
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
