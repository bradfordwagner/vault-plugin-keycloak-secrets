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
// engine's least-privilege admin client in master.
func (h *harness) setupKeycloak(ctx context.Context, t *testing.T) {
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
		"standardFlowEnabled":    false,
		"attributes":             map[string]string{"it.marker": "from-template"},
	})
	step(err)
	tplSA, err := kc.serviceAccountUser(ctx, realm, tplID)
	step(err)
	step(kc.grantRealmRoles(ctx, realm, tplSA, templateRole))

	// Engine admin client in master, granted exactly the roles docs/admin-client.md
	// lists, plus manage-clients on master itself so config/rotate can regenerate
	// its own secret.
	if existing, err := kc.findClient(ctx, "master", adminClient); err != nil {
		t.Fatal(err)
	} else if existing != nil {
		_, err = kc.must(ctx, http.MethodDelete, "/admin/realms/master/clients/"+existing["id"].(string), nil, http.StatusNoContent)
		step(err)
	}
	adminID, err := kc.createClient(ctx, "master", map[string]interface{}{
		"clientId":                  adminClient,
		"enabled":                   true,
		"publicClient":              false,
		"serviceAccountsEnabled":    true,
		"standardFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
	})
	step(err)
	adminSA, err := kc.serviceAccountUser(ctx, "master", adminID)
	step(err)
	step(kc.grantClientRoles(ctx, "master", adminSA, realm+"-realm", "manage-clients", "manage-users", "view-realm"))
	step(kc.grantClientRoles(ctx, "master", adminSA, "master-realm", "manage-clients"))
	h.adminSec, err = kc.clientSecret(ctx, "master", adminID)
	step(err)
}

// setupVault (re)mounts the engine and writes its config and roles.
func (h *harness) setupVault(ctx context.Context, t *testing.T) {
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
	write("config", map[string]interface{}{
		// Vault reaches Keycloak over the compose network, not localhost.
		"server_url":    env("KEYCLOAK_URL_FROM_VAULT", "http://keycloak:8080"),
		"auth_realm":    "master",
		"client_id":     adminClient,
		"client_secret": h.adminSec,
		// Off so the periodic tick cannot rotate mid-test; rotation is driven
		// explicitly through config/rotate below.
		"rotation_period": 0,
	})
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
	h.setupKeycloak(ctx, t)
	h.setupVault(ctx, t)

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
		status, _, err := postToken(ctx, h.httpc, h.kcURL, "master", url.Values{
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
