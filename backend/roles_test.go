package backend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// newTestBackend sets up a backend for role storage tests. logical.TestBackendConfig
// does not populate StorageView, so callers must pass their own storage in each
// request.
func newTestBackend(t *testing.T) *backend {
	t.Helper()
	b := newBackend()
	if err := b.Setup(context.Background(), logical.TestBackendConfig()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return b
}

// TestRolesCreateRequiresSourceClientID verifies that creating a role without
// source_client_id returns an error response, and that once set the role
// round-trips through read with its ttl/max_ttl preserved.
func TestRolesCreateRequiresSourceClientID(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	// Create without source_client_id -> error response.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "realm/test-realm/roles/app",
		Data: map[string]interface{}{
			"ttl":     60,
			"max_ttl": 120,
		},
		Storage: storage,
	})
	if err != nil {
		t.Fatalf("create without source_client_id: unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("create without source_client_id: expected error response, got %#v", resp)
	}

	// Create with source_client_id + ttl/max_ttl succeeds.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "realm/test-realm/roles/app",
		Data: map[string]interface{}{
			"source_client_id": "source-app",
			"ttl":              60,
			"max_ttl":          120,
			"realm_roles":      "role-a,role-b",
		},
		Storage: storage,
	})
	if err != nil {
		t.Fatalf("create with source_client_id: unexpected err: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("create with source_client_id: unexpected error response: %#v", resp)
	}

	// Read it back and confirm the round-trip.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "realm/test-realm/roles/app",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read role: unexpected err: %v", err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatalf("read role: expected data, got %#v", resp)
	}
	if got := resp.Data["source_client_id"]; got != "source-app" {
		t.Errorf("source_client_id = %v, want source-app", got)
	}
	if got := resp.Data["ttl"]; got != int64(60) {
		t.Errorf("ttl = %v, want 60", got)
	}
	if got := resp.Data["max_ttl"]; got != int64(120) {
		t.Errorf("max_ttl = %v, want 120", got)
	}
	roles, ok := resp.Data["realm_roles"].([]string)
	if !ok || len(roles) != 2 || roles[0] != "role-a" || roles[1] != "role-b" {
		t.Errorf("realm_roles = %#v, want [role-a role-b]", resp.Data["realm_roles"])
	}
}

// TestRolesTTLGreaterThanMaxTTL verifies the ttl<=max_ttl validation still holds
// under the new schema.
func TestRolesTTLGreaterThanMaxTTL(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "realm/test-realm/roles/app",
		Data: map[string]interface{}{
			"source_client_id": "source-app",
			"ttl":              300,
			"max_ttl":          120,
		},
		Storage: storage,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response for ttl > max_ttl, got %#v", resp)
	}
}
