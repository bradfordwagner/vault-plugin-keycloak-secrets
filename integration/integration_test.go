//go:build integration

// Package integration runs the engine end to end against a real Keycloak and
// a real dev-mode Vault (see docker-compose.yml). Run it with:
//
//	task integration
//
// or, against an already-running stack:
//
//	go test -tags integration -v ./integration/...
package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/bradfordwagner/vault-plugin-keycloak-secrets/client"
)

const (
	pluginName     = "vault-plugin-keycloak-secrets"
	mount          = "keycloak"
	realm          = "vkp-it"
	templateClient = "it-template"
	adminClient    = "vault-keycloak-secrets-admin"
	templateRole   = "it-template-role" // granted to the template, copied onto clones
	extraRole      = "it-extra-role"    // granted only through the engine role's realm_roles
)

// authRealms are the realms the engine's admin client lives in: master, and the
// target realm itself, where only its realm-management roles exist.
var authRealms = []string{"master", realm}

// redirectURIs are the template's redirect URIs, one per name users reach
// Keycloak by. Clones must carry both.
var redirectURIs = []string{
	"https://app.clustera.dev.bradfordwagner.com/callback",
	"https://app.dev.bradfordwagner.com/callback",
}

// serverURLs are the URLs Vault dials Keycloak by over the compose network:
// the per-cluster A record, the CNAME in front of it, and the admin-only name
// (see dns/), each through the ingress over plain HTTP and over TLS.
func serverURLs() []string {
	return strings.Split(env("KEYCLOAK_URLS_FROM_VAULT", strings.Join([]string{
		"http://keycloak.clustera.dev.bradfordwagner.com:8080",
		"http://keycloak.dev.bradfordwagner.com:8080",
		"http://keycloak-admin.clustera.dev.bradfordwagner.com:8080",
		"https://keycloak.clustera.dev.bradfordwagner.com",
		"https://keycloak.dev.bradfordwagner.com",
		"https://keycloak-admin.clustera.dev.bradfordwagner.com",
	}, ",")), ",")
}

// ingressCA returns the PEM root the ingress signs its certificates with,
// passed to the engine as ca_cert for https server URLs.
func ingressCA(ctx context.Context, t *testing.T) string {
	t.Helper()
	if pem := os.Getenv("KEYCLOAK_CA_PEM"); pem != "" {
		return pem
	}
	var pem string
	if err := waitFor(ctx, time.Minute, "ingress root CA", func() error {
		out, err := exec.Command("docker", "compose", "-f", "docker-compose.yml",
			"exec", "-T", "ingress", "cat", "/data/caddy/pki/authorities/local/root.crt").Output()
		if err != nil {
			return err
		}
		pem = string(out)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return pem
}

// assertCNAME checks that Vault resolves the CNAME name through the dns
// service, so the two names keep exercising a real CNAME and A record.
func assertCNAME(t *testing.T) {
	t.Helper()
	if os.Getenv("KEYCLOAK_URLS_FROM_VAULT") != "" {
		return
	}
	out, err := exec.Command("docker", "compose", "-f", "docker-compose.yml",
		"exec", "-T", "vault", "nslookup", "keycloak.dev.bradfordwagner.com").CombinedOutput()
	if err != nil {
		t.Fatalf("nslookup from vault: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "canonical name = keycloak.clustera.dev.bradfordwagner.com") {
		t.Fatalf("keycloak.dev.bradfordwagner.com is not a CNAME to the cluster A record:\n%s", out)
	}
}

// env returns the named variable or def when unset.
func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

type harness struct {
	kc       *kcAdmin
	kcURL    string // Keycloak as the test process reaches it
	vault    *api.Client
	creds    *client.Client
	httpc    *http.Client
	adminSec string // seed secret for the engine's admin client

	authRealm string // realm the engine's admin client lives in
	caPEM     string // ingress root CA, for https server URLs
}

// composeURL returns the loopback URL of a compose service's container port.
// The compose file binds host ports at random, so they are looked up here.
func composeURL(t *testing.T, service, port string) string {
	t.Helper()
	out, err := exec.Command("docker", "compose", "-f", "docker-compose.yml", "port", service, port).Output()
	if err != nil {
		t.Fatalf("docker compose port %s %s (is the stack up?): %v", service, port, err)
	}
	addr := strings.TrimSpace(string(out))
	i := strings.LastIndex(addr, ":")
	if i < 0 || i == len(addr)-1 {
		t.Fatalf("docker compose port %s %s: unexpected output %q", service, port, addr)
	}
	// The compose file binds 127.0.0.1 only; "localhost" may resolve to ::1 first.
	return "http://127.0.0.1:" + addr[i+1:]
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	httpc := &http.Client{Timeout: 30 * time.Second}
	kcURL := os.Getenv("KEYCLOAK_URL")
	if kcURL == "" {
		kcURL = composeURL(t, "keycloak", "8080")
	}
	kcURL = strings.TrimRight(kcURL, "/")

	// The test unmounts and remounts the engine, so it must never follow an
	// ambient VAULT_ADDR / VAULT_TOKEN / VAULT_NAMESPACE that points at a real
	// Vault. Only the INTEGRATION_* overrides select a different target.
	vcfg := api.DefaultConfig()
	vcfg.Address = os.Getenv("INTEGRATION_VAULT_ADDR")
	if vcfg.Address == "" {
		vcfg.Address = composeURL(t, "vault", "8200")
	}
	vc, err := api.NewClient(vcfg)
	if err != nil {
		t.Fatal(err)
	}
	vc.SetToken(env("INTEGRATION_VAULT_TOKEN", "root"))
	vc.ClearNamespace()

	return &harness{
		kc: &kcAdmin{
			baseURL:  kcURL,
			user:     env("KEYCLOAK_ADMIN_USER", "admin"),
			password: env("KEYCLOAK_ADMIN_PASSWORD", "admin"),
			http:     httpc,
		},
		kcURL: kcURL,
		vault: vc,
		creds: client.New(vc, mount),
		httpc: httpc,
	}
}

// waitReady blocks until both Keycloak and Vault answer.
func (h *harness) waitReady(ctx context.Context, t *testing.T) {
	t.Helper()
	if err := waitFor(ctx, 3*time.Minute, "keycloak admin login", func() error {
		_, err := h.kc.token(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := waitFor(ctx, time.Minute, "vault", func() error {
		_, err := h.vault.Sys().HealthWithContext(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// setupKeycloak (re)creates the test realm, the template client and the
// engine's least-privilege admin client in authRealm.
func (h *harness) setupKeycloak(ctx context.Context, t *testing.T, authRealm string) {
	t.Helper()
	kc := h.kc
	step := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	_, err := kc.must(ctx, http.MethodDelete, "/admin/realms/"+realm, nil, http.StatusNoContent, http.StatusNotFound)
	step(err)
	_, err = kc.must(ctx, http.MethodPost, "/admin/realms", map[string]interface{}{
		"realm": realm, "enabled": true,
	}, http.StatusCreated)
	step(err)
	for _, r := range []string{templateRole, extraRole} {
		_, err = kc.must(ctx, http.MethodPost, "/admin/realms/"+realm+"/roles",
			map[string]interface{}{"name": r}, http.StatusCreated)
		step(err)
	}

	// Template client: a confidential service-account client whose service
	// account holds templateRole. Clones must inherit both.
	tplID, err := kc.createClient(ctx, realm, map[string]interface{}{
		"clientId":               templateClient,
		"enabled":                true,
		"publicClient":           false,
		"serviceAccountsEnabled": true,
		"standardFlowEnabled":    true,
		"redirectUris":           redirectURIs,
		"attributes":             map[string]string{"it.marker": "from-template"},
	})
	step(err)
	tplSA, err := kc.serviceAccountUser(ctx, realm, tplID)
	step(err)
	step(kc.grantRealmRoles(ctx, realm, tplSA, templateRole))

	// Engine admin client, granted exactly the roles docs/admin-client.md lists,
	// plus manage-clients on its own realm so config/rotate can regenerate its
	// own secret. Outside master those roles all live on realm-management.
	h.authRealm = authRealm
	if existing, err := kc.findClient(ctx, authRealm, adminClient); err != nil {
		t.Fatal(err)
	} else if existing != nil {
		_, err = kc.must(ctx, http.MethodDelete, "/admin/realms/"+authRealm+"/clients/"+existing["id"].(string), nil, http.StatusNoContent)
		step(err)
	}
	adminID, err := kc.createClient(ctx, authRealm, map[string]interface{}{
		"clientId":                  adminClient,
		"enabled":                   true,
		"publicClient":              false,
		"serviceAccountsEnabled":    true,
		"standardFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
	})
	step(err)
	// Keycloak 26.8.2+ rejects admin API tokens lacking the kc-admin-api audience.
	step(kc.addDefaultClientScope(ctx, authRealm, adminID, "kc-admin-api"))
	adminSA, err := kc.serviceAccountUser(ctx, authRealm, adminID)
	step(err)
	if authRealm == "master" {
		step(kc.grantClientRoles(ctx, "master", adminSA, realm+"-realm", "manage-clients", "manage-users", "view-realm"))
		step(kc.grantClientRoles(ctx, "master", adminSA, "master-realm", "manage-clients"))
	} else {
		step(kc.grantClientRoles(ctx, authRealm, adminSA, "realm-management", "manage-clients", "manage-users", "view-realm"))
	}
	h.adminSec, err = kc.clientSecret(ctx, authRealm, adminID)
	step(err)
}

// setupVault (re)mounts the engine and writes its config and roles.
func (h *harness) setupVault(ctx context.Context, t *testing.T, serverURL string) {
	t.Helper()
	sys := h.vault.Sys()
	if mounts, err := sys.ListMountsWithContext(ctx); err != nil {
		t.Fatal(err)
	} else if _, ok := mounts[mount+"/"]; ok {
		if err := sys.UnmountWithContext(ctx, mount); err != nil {
			t.Fatal(err)
		}
	}
	if err := sys.MountWithContext(ctx, mount, &api.MountInput{Type: pluginName}); err != nil {
		t.Fatalf("mount %s (is the plugin in -dev-plugin-dir?): %v", pluginName, err)
	}

	write := func(path string, data map[string]interface{}) {
		t.Helper()
		if _, err := h.vault.Logical().WriteWithContext(ctx, mount+"/"+path, data); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	cfg := map[string]interface{}{
		"server_url":    serverURL,
		"auth_realm":    h.authRealm,
		"client_id":     adminClient,
		"client_secret": h.adminSec,
		// Off so the periodic tick cannot rotate mid-test; rotation is driven
		// explicitly through config/rotate below.
		"rotation_period": 0,
	}
	if strings.HasPrefix(serverURL, "https://") {
		cfg["ca_cert"] = h.caPEM
	}
	write("config", cfg)
	write("realm/"+realm+"/roles/app", map[string]interface{}{
		"source_client_id": templateClient,
		"realm_roles":      extraRole,
		"ttl":              "5m",
		"max_ttl":          "10m",
	})
	write("realm/"+realm+"/roles/short", map[string]interface{}{
		"source_client_id": templateClient,
		"ttl":              "5s",
		"max_ttl":          "5s",
	})
}

// clientCredentials runs a client_credentials grant with issued credentials.
func (h *harness) clientCredentials(ctx context.Context, c *client.Credentials) (int, string, error) {
	status, body, err := postToken(ctx, h.httpc, h.kcURL, realm, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
	})
	return status, string(body), err
}

// assertWorks checks the credentials authenticate and carry the expected roles.
func (h *harness) assertWorks(ctx context.Context, t *testing.T, c *client.Credentials, wantRoles ...string) {
	t.Helper()
	tok, err := grantToken(ctx, h.httpc, h.kcURL, realm, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
	})
	if err != nil {
		t.Fatalf("issued credentials do not authenticate: %v", err)
	}
	roles, err := jwtRealmRoles(tok)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range wantRoles {
		if !slices.Contains(roles, r) {
			t.Errorf("token realm roles %v missing %q", roles, r)
		}
	}
}

// waitGone waits until clientID no longer exists and its credentials fail.
func (h *harness) waitGone(ctx context.Context, t *testing.T, c *client.Credentials, timeout time.Duration) {
	t.Helper()
	if err := waitFor(ctx, timeout, "client "+c.ClientID+" deletion", func() error {
		got, err := h.kc.findClient(ctx, realm, c.ClientID)
		if err != nil {
			return err
		}
		if got != nil {
			return fmt.Errorf("client still exists")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	status, body, err := h.clientCredentials(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if status == http.StatusOK {
		t.Fatalf("deleted client still authenticates: %s", body)
	}
}

func TestEngine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	h := newHarness(t)
	h.waitReady(ctx, t)
	assertCNAME(t)
	h.caPEM = ingressCA(ctx, t)

	for _, serverURL := range serverURLs() {
		for _, authRealm := range authRealms {
			name := strings.Replace(serverURL, "://", "/", 1) + "/auth_realm=" + authRealm
			t.Run(name, func(t *testing.T) {
				// Fresh admin client per run: the rotation subtest retires the seed secret.
				h.setupKeycloak(ctx, t, authRealm)
				h.setupVault(ctx, t, serverURL)
				h.engineTests(ctx, t)
			})
		}
	}
}

// engineTests drives the engine through its lifecycle against one server_url.
func (h *harness) engineTests(ctx context.Context, t *testing.T) {
	t.Run("issue, renew, revoke", func(t *testing.T) {
		creds, err := h.creds.Issue(ctx, realm, "app")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(creds.ClientID, templateClient+"-vkp-") {
			t.Errorf("client_id %q lacks prefix %q", creds.ClientID, templateClient+"-vkp-")
		}
		if creds.Realm != realm {
			t.Errorf("realm = %q, want %q", creds.Realm, realm)
		}
		if creds.LeaseID == "" || !creds.Renewable {
			t.Errorf("lease_id=%q renewable=%v, want a renewable lease", creds.LeaseID, creds.Renewable)
		}
		if creds.LeaseDuration != 5*time.Minute {
			t.Errorf("lease duration = %s, want 5m", creds.LeaseDuration)
		}

		h.assertWorks(ctx, t, creds, templateRole, extraRole)

		// The clone inherits template config and carries vkp tracking.
		got, err := h.kc.findClient(ctx, realm, creds.ClientID)
		if err != nil || got == nil {
			t.Fatalf("clone %q not found in Keycloak: %v", creds.ClientID, err)
		}
		attrs, _ := got["attributes"].(map[string]interface{})
		for k, want := range map[string]string{
			"it.marker":            "from-template",
			"vkp.managed":          "true",
			"vkp.source_client_id": templateClient,
			"vkp.realm":            realm,
			"vkp.role":             "app",
		} {
			if attrs[k] != want {
				t.Errorf("clone attribute %s = %v, want %q", k, attrs[k], want)
			}
		}
		var gotURIs []string
		uris, _ := got["redirectUris"].([]interface{})
		for _, u := range uris {
			gotURIs = append(gotURIs, u.(string))
		}
		slices.Sort(gotURIs)
		if !slices.Equal(gotURIs, redirectURIs) {
			t.Errorf("clone redirectUris = %v, want %v", gotURIs, redirectURIs)
		}

		d, err := h.creds.Renew(ctx, creds.LeaseID, 0)
		if err != nil {
			t.Fatal(err)
		}
		if d <= 0 {
			t.Errorf("renewed lease duration = %s, want > 0", d)
		}

		if err := h.creds.Revoke(ctx, creds.LeaseID); err != nil {
			t.Fatal(err)
		}
		h.waitGone(ctx, t, creds, 30*time.Second)
	})

	t.Run("lease expiry deletes client", func(t *testing.T) {
		creds, err := h.creds.Issue(ctx, realm, "short")
		if err != nil {
			t.Fatal(err)
		}
		h.assertWorks(ctx, t, creds, templateRole)
		h.waitGone(ctx, t, creds, 90*time.Second)
	})

	t.Run("admin secret rotation", func(t *testing.T) {
		if _, err := h.vault.Logical().WriteWithContext(ctx, mount+"/config/rotate", nil); err != nil {
			t.Fatal(err)
		}
		cfg, err := h.vault.Logical().ReadWithContext(ctx, mount+"/config")
		if err != nil {
			t.Fatal(err)
		}
		if lr := fmt.Sprint(cfg.Data["last_rotated"]); lr == "0" || lr == "<nil>" {
			t.Fatalf("last_rotated = %s after rotate, want a timestamp", lr)
		}
		status, _, err := postToken(ctx, h.httpc, h.kcURL, h.authRealm, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {adminClient},
			"client_secret": {h.adminSec},
		})
		if err != nil {
			t.Fatal(err)
		}
		if status == http.StatusOK {
			t.Error("seed admin secret still works after rotation")
		}

		// The engine keeps working on the rotated secret.
		creds, err := h.creds.Issue(ctx, realm, "app")
		if err != nil {
			t.Fatalf("issue after rotation: %v", err)
		}
		h.assertWorks(ctx, t, creds, templateRole, extraRole)
		if err := h.creds.Revoke(ctx, creds.LeaseID); err != nil {
			t.Fatal(err)
		}
		h.waitGone(ctx, t, creds, 30*time.Second)
	})
}
