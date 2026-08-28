package backend

import (
	"testing"
)

func TestBuildCloneRepresentation(t *testing.T) {
	src := map[string]interface{}{
		"id":                      "src-uuid-1234",
		"clientId":                "template-app",
		"secret":                  "super-secret",
		"registrationAccessToken": "reg-token",
		"publicClient":            true,
		"clientAuthenticatorType": "client-jwt",
		"attributes": map[string]interface{}{
			"post.logout.redirect.uris": "+",
		},
		"defaultClientScopes": []interface{}{"web-origins", "roles"},
		"protocolMappers": []interface{}{
			map[string]interface{}{
				"id":             "mapper-uuid-1",
				"name":           "audience",
				"protocol":       "openid-connect",
				"protocolMapper": "oidc-audience-mapper",
			},
		},
	}

	got := buildCloneRepresentation(src, "clone-app")

	// Stripped fields must be absent.
	for _, k := range []string{"id", "secret", "registrationAccessToken"} {
		if _, ok := got[k]; ok {
			t.Errorf("expected key %q to be stripped from clone, but it is present", k)
		}
	}

	// clientId is set to the passed value.
	if got["clientId"] != "clone-app" {
		t.Errorf("clientId = %v, want %q", got["clientId"], "clone-app")
	}

	// Forced confidential.
	if got["publicClient"] != false {
		t.Errorf("publicClient = %v, want false", got["publicClient"])
	}
	if got["clientAuthenticatorType"] != "client-secret" {
		t.Errorf("clientAuthenticatorType = %v, want %q", got["clientAuthenticatorType"], "client-secret")
	}

	// Enabled.
	if got["enabled"] != true {
		t.Errorf("enabled = %v, want true", got["enabled"])
	}

	// protocolMappers: element has no id, retains other keys.
	mappers, ok := got["protocolMappers"].([]interface{})
	if !ok || len(mappers) != 1 {
		t.Fatalf("protocolMappers = %v, want a slice of length 1", got["protocolMappers"])
	}
	mapper, ok := mappers[0].(map[string]interface{})
	if !ok {
		t.Fatalf("protocolMappers[0] = %v, want a map", mappers[0])
	}
	if _, ok := mapper["id"]; ok {
		t.Errorf("protocolMappers[0] still has an id, want it stripped")
	}
	if mapper["name"] != "audience" {
		t.Errorf("protocolMappers[0][name] = %v, want %q", mapper["name"], "audience")
	}
	if mapper["protocolMapper"] != "oidc-audience-mapper" {
		t.Errorf("protocolMappers[0][protocolMapper] = %v, want %q", mapper["protocolMapper"], "oidc-audience-mapper")
	}

	// Arbitrary fields preserved.
	if _, ok := got["attributes"]; !ok {
		t.Errorf("expected attributes to be preserved in clone")
	}
	if _, ok := got["defaultClientScopes"]; !ok {
		t.Errorf("expected defaultClientScopes to be preserved in clone")
	}

	// The original src map must be unmodified.
	if src["id"] != "src-uuid-1234" {
		t.Errorf("src id = %v, want it unchanged (%q)", src["id"], "src-uuid-1234")
	}
	if src["publicClient"] != true {
		t.Errorf("src publicClient = %v, want it unchanged (true)", src["publicClient"])
	}
	if src["clientAuthenticatorType"] != "client-jwt" {
		t.Errorf("src clientAuthenticatorType = %v, want it unchanged (%q)", src["clientAuthenticatorType"], "client-jwt")
	}
	if src["clientId"] != "template-app" {
		t.Errorf("src clientId = %v, want it unchanged (%q)", src["clientId"], "template-app")
	}
	// src's protocol mapper must still have its id (not mutated).
	srcMappers, _ := src["protocolMappers"].([]interface{})
	if len(srcMappers) == 1 {
		if srcMapper, ok := srcMappers[0].(map[string]interface{}); ok {
			if srcMapper["id"] != "mapper-uuid-1" {
				t.Errorf("src protocolMappers[0][id] = %v, want it unchanged (%q)", srcMapper["id"], "mapper-uuid-1")
			}
		}
	}
}
