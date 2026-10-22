// Package client is a small consumer-side helper for this secrets engine. It
// wraps a Vault API client and issues, renews and revokes dynamic Keycloak
// client credentials (client_id + client_secret) from a mounted engine.
//
//	vc, _ := api.NewClient(api.DefaultConfig()) // VAULT_ADDR / VAULT_TOKEN
//	c := client.New(vc, "keycloak")
//	creds, err := c.Issue(ctx, "my-realm", "my-role")
//	...
//	defer c.Revoke(ctx, creds.LeaseID)
package client

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

// Credentials is one issued Keycloak client and the Vault lease that owns it.
// The Keycloak client is deleted when the lease expires or is revoked.
type Credentials struct {
	ClientID      string        `json:"client_id"`
	ClientSecret  string        `json:"client_secret"`
	Realm         string        `json:"realm"`
	LeaseID       string        `json:"lease_id"`
	LeaseDuration time.Duration `json:"lease_duration"`
	Renewable     bool          `json:"renewable"`
}

// Client issues credentials from one engine mount.
type Client struct {
	vault *api.Client
	mount string
}

// New returns a Client for the engine mounted at mount (e.g. "keycloak").
func New(vault *api.Client, mount string) *Client {
	return &Client{vault: vault, mount: strings.Trim(mount, "/")}
}

// CredsPath returns the Vault path whose read issues credentials for a role.
func (c *Client) CredsPath(realm, role string) string {
	return c.mount + "/realm/" + url.PathEscape(realm) + "/creds/" + url.PathEscape(role)
}

// Issue reads realm/<realm>/creds/<role>, which clones the role's template
// client in Keycloak and returns the clone's credentials under a new lease.
func (c *Client) Issue(ctx context.Context, realm, role string) (*Credentials, error) {
	path := c.CredsPath(realm, role)
	secret, err := c.vault.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("read %s: empty response", path)
	}

	clientID, _ := secret.Data["client_id"].(string)
	clientSecret, _ := secret.Data["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("read %s: response is missing client_id or client_secret", path)
	}
	gotRealm, _ := secret.Data["realm"].(string)

	return &Credentials{
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Realm:         gotRealm,
		LeaseID:       secret.LeaseID,
		LeaseDuration: time.Duration(secret.LeaseDuration) * time.Second,
		Renewable:     secret.Renewable,
	}, nil
}

// Renew extends a lease and returns the new lease duration. increment is
// passed to Vault, but this engine currently ignores it: every renewal resets
// the lease to the role's ttl, capped at the role's max_ttl.
func (c *Client) Renew(ctx context.Context, leaseID string, increment time.Duration) (time.Duration, error) {
	secret, err := c.vault.Sys().RenewWithContext(ctx, leaseID, int(increment.Seconds()))
	if err != nil {
		return 0, fmt.Errorf("renew lease %s: %w", leaseID, err)
	}
	if secret == nil {
		return 0, fmt.Errorf("renew lease %s: empty response", leaseID)
	}
	return time.Duration(secret.LeaseDuration) * time.Second, nil
}

// Revoke revokes a lease now, which deletes its Keycloak client.
func (c *Client) Revoke(ctx context.Context, leaseID string) error {
	if err := c.vault.Sys().RevokeWithContext(ctx, leaseID); err != nil {
		return fmt.Errorf("revoke lease %s: %w", leaseID, err)
	}
	return nil
}
