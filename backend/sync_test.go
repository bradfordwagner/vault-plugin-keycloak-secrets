package backend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestBuildSyncRepresentation verifies the update representation pins the clone's
// own clientId and internal id, keeps the clone confidential, and omits the
// secret (so Keycloak preserves the clone's current secret on PUT) — all without
// mutating the source.
func TestBuildSyncRepresentation(t *testing.T) {
	src := map[string]interface{}{
		"id":                      "source-internal-id",
		"clientId":                "root",
		"secret":                  "source-secret",
		"publicClient":            true,
		"clientAuthenticatorType": "client-jwt",
		"attributes":              map[string]interface{}{"foo": "bar"},
	}

	rep := buildSyncRepresentation(src, "root-vkp-123", "clone-internal-id")

	if rep["id"] != "clone-internal-id" {
		t.Errorf("id = %v, want clone-internal-id", rep["id"])
	}
	if rep["clientId"] != "root-vkp-123" {
		t.Errorf("clientId = %v, want root-vkp-123", rep["clientId"])
	}
	if _, ok := rep["secret"]; ok {
		t.Error("secret must be absent so Keycloak preserves the clone's existing secret")
	}
	if rep["publicClient"] != false {
		t.Errorf("publicClient = %v, want false (forced confidential)", rep["publicClient"])
	}
	if rep["clientAuthenticatorType"] != "client-secret" {
		t.Errorf("clientAuthenticatorType = %v, want client-secret", rep["clientAuthenticatorType"])
	}
	if rep["attributes"] == nil {
		t.Error("attributes should be carried over from source")
	}

	// Source must be untouched.
	if src["id"] != "source-internal-id" || src["secret"] != "source-secret" || src["publicClient"] != true {
		t.Error("buildSyncRepresentation mutated the source representation")
	}
}

// TestHashRepStableAndSensitive confirms the digest is stable for equal
// representations and changes when the representation changes.
func TestHashRepStableAndSensitive(t *testing.T) {
	a := map[string]interface{}{"clientId": "root", "enabled": true, "attributes": map[string]interface{}{"x": "1"}}
	b := map[string]interface{}{"attributes": map[string]interface{}{"x": "1"}, "enabled": true, "clientId": "root"}

	ha, err := hashRep(a)
	if err != nil {
		t.Fatalf("hashRep(a): %v", err)
	}
	hb, err := hashRep(b)
	if err != nil {
		t.Fatalf("hashRep(b): %v", err)
	}
	if ha != hb {
		t.Errorf("hash differs for equal representations: %s vs %s", ha, hb)
	}

	a["enabled"] = false
	hc, _ := hashRep(a)
	if hc == ha {
		t.Error("hash did not change after mutating the representation")
	}
}

// TestCloneRecordRoundTrip exercises the clone index storage helpers.
func TestCloneRecordRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := &logical.InmemStorage{}

	rec1 := cloneRecord{CloneClientID: "root-vkp-1", InternalID: "int-1"}
	rec2 := cloneRecord{CloneClientID: "root-vkp-2", InternalID: "int-2"}
	if err := writeCloneRecord(ctx, s, "test-realm", "app", rec1); err != nil {
		t.Fatalf("write rec1: %v", err)
	}
	if err := writeCloneRecord(ctx, s, "test-realm", "app", rec2); err != nil {
		t.Fatalf("write rec2: %v", err)
	}

	recs, err := listCloneRecords(ctx, s, "test-realm", "app")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d clone records, want 2", len(recs))
	}

	if err := deleteCloneRecord(ctx, s, "test-realm", "app", "int-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	recs, _ = listCloneRecords(ctx, s, "test-realm", "app")
	if len(recs) != 1 || recs[0].InternalID != "int-2" {
		t.Fatalf("after delete got %+v, want only int-2", recs)
	}
}

// TestRoleSyncUpstreamRoundTrip verifies the sync_upstream flag persists and is
// returned on read.
func TestRoleSyncUpstreamRoundTrip(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	if err := b.Setup(ctx, logical.TestBackendConfig()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	s := &logical.InmemStorage{}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "realm/test-realm/roles/app",
		Data: map[string]interface{}{
			"source_client_id": "source-app",
			"sync_upstream":    true,
			"ttl":              60,
			"max_ttl":          120,
		},
		Storage: s,
	}); err != nil {
		t.Fatalf("create role: %v", err)
	}

	role, err := getRole(ctx, s, "test-realm", "app")
	if err != nil {
		t.Fatalf("getRole: %v", err)
	}
	if role == nil || !role.SyncUpstream {
		t.Fatalf("sync_upstream did not persist: %+v", role)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "realm/test-realm/roles/app",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("read role: %v", err)
	}
	if resp.Data["sync_upstream"] != true {
		t.Errorf("read sync_upstream = %v, want true", resp.Data["sync_upstream"])
	}
}
