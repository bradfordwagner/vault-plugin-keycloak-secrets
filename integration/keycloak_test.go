//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// kcAdmin drives Keycloak's Admin REST API as the bootstrap admin user. It is
// test scaffolding only: it builds the realm, template client and the engine's
// admin client the plugin is then pointed at.
type kcAdmin struct {
	baseURL  string
	user     string
	password string
	http     *http.Client

	tok    string    // cached admin access token
	tokExp time.Time // when to stop reusing tok
}

// token returns a cached admin token, minting a new one shortly before the
// cached one expires. Master-realm tokens live for 60s by default, which is
// shorter than a full test run.
func (k *kcAdmin) token(ctx context.Context) (string, error) {
	if k.tok != "" && time.Now().Before(k.tokExp) {
		return k.tok, nil
	}
	status, body, err := postToken(ctx, k.http, k.baseURL, "master", url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {k.user},
		"password":   {k.password},
	})
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("admin token grant: status %d: %s", status, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	k.tok = out.AccessToken
	// Refresh 10s early so a token never expires mid-request.
	k.tokExp = time.Now().Add(time.Duration(out.ExpiresIn)*time.Second - 10*time.Second)
	return k.tok, nil
}

// do issues an admin call and returns the status code and body. in, when set,
// is JSON-encoded.
func (k *kcAdmin) do(ctx context.Context, method, path string, in interface{}) (int, []byte, error) {
	tok, err := k.token(ctx)
	if err != nil {
		return 0, nil, err
	}
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.baseURL+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, out, err
}

// must runs do and fails unless the status is one of want.
func (k *kcAdmin) must(ctx context.Context, method, path string, in interface{}, want ...int) ([]byte, error) {
	status, body, err := k.do(ctx, method, path, in)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	for _, w := range want {
		if status == w {
			return body, nil
		}
	}
	return nil, fmt.Errorf("%s %s: status %d: %s", method, path, status, body)
}

// findClient returns the client representation with the given clientId, or nil
// when the realm has none.
func (k *kcAdmin) findClient(ctx context.Context, realm, clientID string) (map[string]interface{}, error) {
	body, err := k.must(ctx, http.MethodGet,
		"/admin/realms/"+realm+"/clients?clientId="+url.QueryEscape(clientID), nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var out []map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out[0], nil
}

// createClient creates a client and returns its internal id.
func (k *kcAdmin) createClient(ctx context.Context, realm string, rep map[string]interface{}) (string, error) {
	if _, err := k.must(ctx, http.MethodPost, "/admin/realms/"+realm+"/clients", rep, http.StatusCreated); err != nil {
		return "", err
	}
	c, err := k.findClient(ctx, realm, rep["clientId"].(string))
	if err != nil {
		return "", err
	}
	if c == nil {
		return "", fmt.Errorf("client %q not found after create", rep["clientId"])
	}
	return c["id"].(string), nil
}

func (k *kcAdmin) serviceAccountUser(ctx context.Context, realm, internalID string) (string, error) {
	body, err := k.must(ctx, http.MethodGet,
		"/admin/realms/"+realm+"/clients/"+internalID+"/service-account-user", nil, http.StatusOK)
	if err != nil {
		return "", err
	}
	var u struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return "", err
	}
	return u.ID, nil
}

func (k *kcAdmin) clientSecret(ctx context.Context, realm, internalID string) (string, error) {
	body, err := k.must(ctx, http.MethodGet,
		"/admin/realms/"+realm+"/clients/"+internalID+"/client-secret", nil, http.StatusOK)
	if err != nil {
		return "", err
	}
	var s struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return "", err
	}
	return s.Value, nil
}

// grantRealmRoles maps realm roles onto a user.
func (k *kcAdmin) grantRealmRoles(ctx context.Context, realm, userID string, names ...string) error {
	var reps []json.RawMessage
	for _, n := range names {
		body, err := k.must(ctx, http.MethodGet, "/admin/realms/"+realm+"/roles/"+url.PathEscape(n), nil, http.StatusOK)
		if err != nil {
			return err
		}
		reps = append(reps, body)
	}
	_, err := k.must(ctx, http.MethodPost,
		"/admin/realms/"+realm+"/users/"+userID+"/role-mappings/realm", reps, http.StatusNoContent)
	return err
}

// grantClientRoles maps roles of the client named roleClientID onto a user.
func (k *kcAdmin) grantClientRoles(ctx context.Context, realm, userID, roleClientID string, names ...string) error {
	c, err := k.findClient(ctx, realm, roleClientID)
	if err != nil {
		return err
	}
	if c == nil {
		return fmt.Errorf("client %q not found in realm %q", roleClientID, realm)
	}
	id := c["id"].(string)
	var reps []json.RawMessage
	for _, n := range names {
		body, err := k.must(ctx, http.MethodGet,
			"/admin/realms/"+realm+"/clients/"+id+"/roles/"+url.PathEscape(n), nil, http.StatusOK)
		if err != nil {
			return err
		}
		reps = append(reps, body)
	}
	_, err = k.must(ctx, http.MethodPost,
		"/admin/realms/"+realm+"/users/"+userID+"/role-mappings/clients/"+id, reps, http.StatusNoContent)
	return err
}

// grantToken runs a token-endpoint grant and returns the access token.
func grantToken(ctx context.Context, hc *http.Client, baseURL, realm string, form url.Values) (string, error) {
	status, body, err := postToken(ctx, hc, baseURL, realm, form)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("token grant in realm %q: status %d: %s", realm, status, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

func postToken(ctx context.Context, hc *http.Client, baseURL, realm string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/realms/"+realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

// jwtRealmRoles decodes (without verifying) an access token's realm roles.
func jwtRealmRoles(token string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims struct {
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims.RealmAccess.Roles, nil
}

// waitFor polls fn until it returns nil or the timeout passes.
func waitFor(ctx context.Context, timeout time.Duration, what string, fn func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := fn()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s: %w", timeout, what, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
