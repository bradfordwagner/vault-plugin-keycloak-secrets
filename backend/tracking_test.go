package backend

import (
	"strings"
	"testing"
	"time"
)

func sampleTrackingInfo() trackingInfo {
	created, _ := time.Parse(time.RFC3339, "2026-08-27T12:00:00Z")
	return trackingInfo{
		SourceClientID: "root",
		Mount:          "keycloak/",
		Realm:          "example",
		Role:           "app",
		CredsPath:      "keycloak/realm/example/creds/app",
		Created:        created,
		TTL:            10 * time.Minute,
		MaxTTL:         time.Hour,
	}
}

func TestTrackingDescriptionAtMint(t *testing.T) {
	desc := sampleTrackingInfo().description()
	for _, want := range []string{
		pluginName,             // created by vkp
		"vkp",                  // marker
		`"root"`,               // source template
		"example/app",          // realm/role
		"Created ",             // when it was created
		"2026-08-27T12:00:00Z", // the created timestamp itself
		"expires by",           // when it will be deleted at the latest
		"2026-08-27T13:00:00Z", // created + max_ttl (1h)
		"DO NOT edit",          // do-not-touch warning
		"vkp.*",                // pointer to the full metadata attributes
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("description missing %q:\n%s", want, desc)
		}
	}
	// The lease id is unobtainable at runtime (see description() doc), so the
	// description must NOT carry a misleading "pending" lease line.
	if strings.Contains(desc, "pending") {
		t.Errorf("description should not mention a pending lease:\n%s", desc)
	}
}

// TestTrackingDescriptionFitsKeycloakColumn guards the varchar(255) limit on
// Keycloak's CLIENT.DESCRIPTION column: exceeding it makes the client
// create/update fail with a Postgres "value too long" 500. Even with an
// abnormally long source client id, the description must stay within the cap.
func TestTrackingDescriptionFitsKeycloakColumn(t *testing.T) {
	info := sampleTrackingInfo()
	info.SourceClientID = strings.Repeat("s", 300)
	desc := info.description()
	if n := len([]rune(desc)); n > keycloakDescriptionMax {
		t.Errorf("description length %d exceeds keycloak max %d:\n%s", n, keycloakDescriptionMax, desc)
	}
}

// TestTrackingDescriptionExpiry checks that the description surfaces the clone's
// lifetime: the exact created+max_ttl expiry when max_ttl is set, and an
// explicit lease-bounded note when it is not.
func TestTrackingDescriptionExpiry(t *testing.T) {
	info := sampleTrackingInfo() // Created 12:00Z, MaxTTL 1h
	desc := info.description()
	if !strings.Contains(desc, "expires by 2026-08-27T13:00:00Z") {
		t.Errorf("description missing exact expiry (created+max_ttl):\n%s", desc)
	}

	info.MaxTTL = 0
	desc = info.description()
	if strings.Contains(desc, "expires by") {
		t.Errorf("description should not claim a fixed expiry when max_ttl is 0:\n%s", desc)
	}
	if !strings.Contains(desc, "no max_ttl") {
		t.Errorf("description should note the absent max_ttl:\n%s", desc)
	}
}

func TestTrackingAttributes(t *testing.T) {
	attrs := sampleTrackingInfo().attributes()
	want := map[string]string{
		trackAttrManaged:      "true",
		trackAttrPlugin:       pluginName,
		trackAttrSourceClient: "root",
		trackAttrMount:        "keycloak/",
		trackAttrRealm:        "example",
		trackAttrRole:         "app",
		trackAttrCreated:      "2026-08-27T12:00:00Z",
		trackAttrMaxExpiry:    "2026-08-27T13:00:00Z",
		trackAttrCredsPath:    "keycloak/realm/example/creds/app",
		trackAttrTTL:          "10m0s",
		trackAttrMaxTTL:       "1h0m0s",
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("attr %q = %q, want %q", k, attrs[k], v)
		}
	}
	// The plugin can never learn its own lease id (SDK logical.Secret.LeaseID is
	// always blank), so no lease-id attribute is ever written.
	if v, ok := attrs["vkp.lease_id"]; ok {
		t.Errorf("vkp.lease_id attr should never be written, got %q", v)
	}
}

func TestTrackingNoMaxTTL(t *testing.T) {
	info := sampleTrackingInfo()
	info.MaxTTL = 0
	// max_expiry is derived from max_ttl, so it is omitted from the attributes when
	// max_ttl is 0 (the description no longer carries expiry — that detail lives in
	// the vkp.* attributes).
	if _, ok := info.attributes()[trackAttrMaxExpiry]; ok {
		t.Error("max_expiry attr should be absent when max_ttl is 0")
	}
}

func TestApplyTrackingPreservesSourceAttributes(t *testing.T) {
	rep := map[string]interface{}{
		"clientId": "root-vkp-1",
		"attributes": map[string]interface{}{
			"existing.source.attr": "keep-me",
		},
	}
	applyTracking(rep, sampleTrackingInfo())

	attrs, ok := rep["attributes"].(map[string]interface{})
	if !ok {
		t.Fatalf("attributes not a map: %T", rep["attributes"])
	}
	if attrs["existing.source.attr"] != "keep-me" {
		t.Errorf("source attribute was dropped: %v", attrs["existing.source.attr"])
	}
	if attrs[trackAttrManaged] != "true" {
		t.Errorf("vkp.managed not stamped: %v", attrs[trackAttrManaged])
	}
	if _, ok := rep["description"].(string); !ok {
		t.Error("description not set")
	}
}

func TestTrackingRoundTripThroughAttributes(t *testing.T) {
	orig := sampleTrackingInfo()

	// Marshal to attributes (as stored on the clone), then reconstruct.
	raw := map[string]interface{}{}
	for k, v := range orig.attributes() {
		raw[k] = v
	}
	got := trackingFromAttributes(raw)

	if got.SourceClientID != orig.SourceClientID ||
		got.Mount != orig.Mount ||
		got.Realm != orig.Realm ||
		got.Role != orig.Role ||
		got.CredsPath != orig.CredsPath ||
		!got.Created.Equal(orig.Created) ||
		got.TTL != orig.TTL ||
		got.MaxTTL != orig.MaxTTL {
		t.Errorf("round trip mismatch:\n orig=%+v\n got =%+v", orig, got)
	}
}

func TestPreserveTrackingKeepsCloneMetadataDropsSourceDescription(t *testing.T) {
	// Freshly built sync rep, derived from the SOURCE client: source description,
	// source attributes, no vkp.* keys.
	rep := map[string]interface{}{
		"clientId":    "root-vkp-1",
		"description": "the source template description",
		"attributes": map[string]interface{}{
			"source.only": "new-value",
		},
	}
	// The clone as it currently exists in Keycloak: tracking description + vkp.*.
	existing := map[string]interface{}{
		"description": "Managed by vault-plugin-keycloak-secrets (vkp): clone of \"root\" for Vault role example/app ...",
		"attributes": map[string]interface{}{
			trackAttrManaged:   "true",
			trackAttrCredsPath: "keycloak/realm/example/creds/app",
			"stale.clone":      "should-not-carry", // non-vkp clone attr must NOT be preserved
		},
	}

	preserveTracking(rep, existing)

	if rep["description"] != existing["description"] {
		t.Errorf("clone tracking description not preserved, got %q", rep["description"])
	}
	attrs := rep["attributes"].(map[string]interface{})
	if attrs[trackAttrCredsPath] != "keycloak/realm/example/creds/app" {
		t.Errorf("vkp.creds_path not preserved: %v", attrs[trackAttrCredsPath])
	}
	if attrs[trackAttrManaged] != "true" {
		t.Errorf("vkp.managed not preserved: %v", attrs[trackAttrManaged])
	}
	if attrs["source.only"] != "new-value" {
		t.Errorf("source attribute change should still propagate: %v", attrs["source.only"])
	}
	if _, ok := attrs["stale.clone"]; ok {
		t.Errorf("non-vkp clone attribute should not be preserved: %v", attrs["stale.clone"])
	}
}
