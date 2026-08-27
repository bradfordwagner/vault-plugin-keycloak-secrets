package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// keycloakClient is a thin wrapper over the Keycloak Admin REST API. It is
// constructed per request from the stored config; it is not cached.
type keycloakClient struct {
	serverURL    string
	authRealm    string // realm used to obtain the admin token
	targetRealm  string // realm the admin methods operate against
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// clientRepresentation mirrors the subset of Keycloak's ClientRepresentation we
// set when creating a client.
type clientRepresentation struct {
	ID                        string            `json:"id,omitempty"`
	ClientID                  string            `json:"clientId"`
	Name                      string            `json:"name,omitempty"`
	Description               string            `json:"description,omitempty"`
	Protocol                  string            `json:"protocol,omitempty"`
	PublicClient              bool              `json:"publicClient"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	Enabled                   bool              `json:"enabled"`
	Attributes                map[string]string `json:"attributes,omitempty"`
	DefaultClientScopes       []string          `json:"defaultClientScopes,omitempty"`
	OptionalClientScopes      []string          `json:"optionalClientScopes,omitempty"`
	RedirectUris              []string          `json:"redirectUris,omitempty"`
}

// roleRepresentation mirrors the subset of Keycloak's RoleRepresentation we use
// when resolving and assigning realm roles.
type roleRepresentation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// newKeycloakClient builds a client from the stored config for the given target
// realm, wiring a custom TLS pool when a CA certificate is provided. The admin
// token is always minted against the config's auth realm (default master), while
// admin methods operate against targetRealm.
func newKeycloakClient(cfg *config, targetRealm string) (*keycloakClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}

	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, fmt.Errorf("failed to parse ca_cert PEM")
		}
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		}
	}

	authRealm := cfg.AuthRealm
	if authRealm == "" {
		authRealm = "master"
	}

	return &keycloakClient{
		serverURL:    strings.TrimRight(cfg.ServerURL, "/"),
		authRealm:    authRealm,
		targetRealm:  targetRealm,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		httpClient:   httpClient,
	}, nil
}

// token obtains an admin access token via the client_credentials grant.
func (c *keycloakClient) token(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.serverURL, c.authRealm)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("keycloak token request failed: status %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("keycloak token response contained no access_token")
	}
	return out.AccessToken, nil
}

// doAdmin issues an authenticated Admin REST call, JSON-encoding in when set and
// returning the raw response body alongside the response.
func (c *keycloakClient) doAdmin(ctx context.Context, token, method, reqURL string, in interface{}) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return nil, nil, err
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	return resp, body, nil
}

// createClient creates a client in the target realm and returns its internal
// id, parsed from the Location header.
func (c *keycloakClient) createClient(ctx context.Context, token string, cr *clientRepresentation) (string, error) {
	reqURL := fmt.Sprintf("%s/admin/realms/%s/clients", c.serverURL, c.targetRealm)
	resp, body, err := c.doAdmin(ctx, token, http.MethodPost, reqURL, cr)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("keycloak create client failed: status %d: %s", resp.StatusCode, string(body))
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("keycloak create client returned no Location header")
	}
	id := loc[strings.LastIndex(loc, "/")+1:]
	if id == "" || id == loc {
		return "", fmt.Errorf("could not parse client id from Location header %q", loc)
	}
	return id, nil
}

// getClientSecret fetches the generated client secret for a confidential client.
func (c *keycloakClient) getClientSecret(ctx context.Context, token, id string) (string, error) {
	reqURL := fmt.Sprintf("%s/admin/realms/%s/clients/%s/client-secret", c.serverURL, c.targetRealm, id)
	resp, body, err := c.doAdmin(ctx, token, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("keycloak get client-secret failed: status %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("failed to parse client-secret response: %w", err)
	}
	return out.Value, nil
}

// deleteClient removes a client. It is idempotent: 204 and 404 both count as
// success so revoke never fails on an already-gone client.
func (c *keycloakClient) deleteClient(ctx context.Context, token, id string) error {
	reqURL := fmt.Sprintf("%s/admin/realms/%s/clients/%s", c.serverURL, c.targetRealm, id)
	resp, body, err := c.doAdmin(ctx, token, http.MethodDelete, reqURL, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("keycloak delete client failed: status %d: %s", resp.StatusCode, string(body))
}

// serviceAccountUserID returns the user id of the client's service account.
func (c *keycloakClient) serviceAccountUserID(ctx context.Context, token, id string) (string, error) {
	reqURL := fmt.Sprintf("%s/admin/realms/%s/clients/%s/service-account-user", c.serverURL, c.targetRealm, id)
	resp, body, err := c.doAdmin(ctx, token, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("keycloak get service-account-user failed: status %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("failed to parse service-account-user response: %w", err)
	}
	if out.ID == "" {
		return "", fmt.Errorf("service-account-user response contained no id")
	}
	return out.ID, nil
}

// realmRole resolves a realm role by name, returning its id and name.
func (c *keycloakClient) realmRole(ctx context.Context, token, name string) (*roleRepresentation, error) {
	reqURL := fmt.Sprintf("%s/admin/realms/%s/roles/%s", c.serverURL, c.targetRealm, url.PathEscape(name))
	resp, body, err := c.doAdmin(ctx, token, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("keycloak get realm role %q failed: status %d: %s", name, resp.StatusCode, string(body))
	}

	var out roleRepresentation
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("failed to parse realm role response: %w", err)
	}
	return &out, nil
}

// assignRealmRoles grants the given realm roles to a user (typically a service
// account user).
func (c *keycloakClient) assignRealmRoles(ctx context.Context, token, userID string, roles []roleRepresentation) error {
	reqURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/role-mappings/realm", c.serverURL, c.targetRealm, userID)
	resp, body, err := c.doAdmin(ctx, token, http.MethodPost, reqURL, roles)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("keycloak assign realm roles failed: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// getClientByClientID resolves a client by its clientId, returning the internal
// (UUID) id. It errors clearly when no client matches.
func (c *keycloakClient) getClientByClientID(ctx context.Context, token, clientID string) (string, error) {
	q := url.Values{}
	q.Set("clientId", clientID)
	reqURL := fmt.Sprintf("%s/admin/realms/%s/clients?%s", c.serverURL, c.targetRealm, q.Encode())
	resp, body, err := c.doAdmin(ctx, token, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("keycloak list clients failed: status %d: %s", resp.StatusCode, string(body))
	}

	var out []clientRepresentation
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("failed to parse clients response: %w", err)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("admin client %q not found in realm %q", clientID, c.targetRealm)
	}
	return out[0].ID, nil
}

// regenerateClientSecret regenerates and returns a new client secret for the
// client identified by its internal (UUID) id. Keycloak's regenerate endpoint
// is a POST to the same path GET client-secret reads.
func (c *keycloakClient) regenerateClientSecret(ctx context.Context, token, internalID string) (string, error) {
	reqURL := fmt.Sprintf("%s/admin/realms/%s/clients/%s/client-secret", c.serverURL, c.targetRealm, internalID)
	resp, body, err := c.doAdmin(ctx, token, http.MethodPost, reqURL, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("keycloak regenerate client-secret failed: status %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("failed to parse client-secret response: %w", err)
	}
	if out.Value == "" {
		return "", fmt.Errorf("keycloak regenerate client-secret response contained no value")
	}
	return out.Value, nil
}
