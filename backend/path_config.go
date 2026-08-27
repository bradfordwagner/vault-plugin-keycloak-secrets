package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// configStoragePath is the single, mount-level storage key for the admin
// connection config. There is one master-global admin credential per mount.
const configStoragePath = "config"

// config holds the connection details and admin credentials used to talk to
// Keycloak's Admin REST API. A single master-global admin client (living in the
// auth realm) administers every other realm served by this mount.
type config struct {
	ServerURL    string `json:"server_url"`
	AuthRealm    string `json:"auth_realm"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CACert       string `json:"ca_cert"`
	// RotationPeriod is the automatic self-rotation interval in seconds; 0
	// disables automatic rotation.
	RotationPeriod int64 `json:"rotation_period_seconds"`
	// LastRotated is the unix-seconds timestamp of the last successful admin
	// secret rotation; set by rotation, not by humans.
	LastRotated int64 `json:"last_rotated"`
}

// pathConfig defines the mount-level config endpoint.
func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"server_url": {
				Type:        framework.TypeString,
				Description: "Base URL of the Keycloak server, e.g. https://keycloak.example.com.",
			},
			"auth_realm": {
				Type:        framework.TypeString,
				Default:     "master",
				Description: "Realm in which the admin client lives and against which the admin token is minted. Defaults to master.",
			},
			"client_id": {
				Type:        framework.TypeString,
				Description: "Client ID of the confidential admin client used to manage Keycloak.",
			},
			"client_secret": {
				Type:        framework.TypeString,
				Description: "Client secret of the admin client.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "Optional PEM-encoded CA certificate used to verify the Keycloak TLS endpoint.",
			},
			"rotation_period": {
				Type:        framework.TypeDurationSecond,
				Description: "Automatic admin secret self-rotation interval in seconds. 0 disables automatic rotation.",
			},
		},
		ExistenceCheck: b.configExists,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		HelpSynopsis:    "Configure the Keycloak connection and master-global admin credentials.",
		HelpDescription: "This endpoint configures the Keycloak server URL and the admin client credentials. A single admin client, living in the auth realm (default master), administers every realm served by this mount.",
	}
}

func (b *backend) configExists(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

// getConfig loads the stored mount-level config, returning nil (no error) when
// unconfigured.
func getConfig(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	cfg := &config{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &config{}
	}

	if v, ok := data.GetOk("server_url"); ok {
		cfg.ServerURL = v.(string)
	}
	if v, ok := data.GetOk("auth_realm"); ok {
		cfg.AuthRealm = v.(string)
	}
	if v, ok := data.GetOk("client_id"); ok {
		cfg.ClientID = v.(string)
	}
	if v, ok := data.GetOk("client_secret"); ok {
		cfg.ClientSecret = v.(string)
	}
	if v, ok := data.GetOk("ca_cert"); ok {
		cfg.CACert = v.(string)
	}
	if v, ok := data.GetOk("rotation_period"); ok {
		cfg.RotationPeriod = int64(v.(int))
	}

	if cfg.AuthRealm == "" {
		cfg.AuthRealm = "master"
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	// Never return client_secret; expose only whether one is set.
	return &logical.Response{
		Data: map[string]interface{}{
			"server_url":        cfg.ServerURL,
			"auth_realm":        cfg.AuthRealm,
			"client_id":         cfg.ClientID,
			"client_secret_set": cfg.ClientSecret != "",
			"ca_cert":           cfg.CACert,
			"rotation_period":   cfg.RotationPeriod,
			"last_rotated":      cfg.LastRotated,
		},
	}, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	return nil, nil
}
