package backend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestConfigRotationPeriodDefault verifies that rotation_period defaults to 1
// day on initial configuration, is preserved across partial updates that omit
// it, and can be explicitly disabled with 0.
func TestConfigRotationPeriodDefault(t *testing.T) {
	b := newBackend()
	cfgConf := logical.TestBackendConfig()
	if err := b.Setup(context.Background(), cfgConf); err != nil {
		t.Fatalf("setup: %v", err)
	}
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	write := func(data map[string]interface{}) {
		t.Helper()
		if _, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data:      data,
			Storage:   storage,
		}); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}

	// Initial create without rotation_period -> defaults to 1 day.
	write(map[string]interface{}{
		"server_url":    "https://kc.example.com",
		"client_id":     "admin-cli",
		"client_secret": "s3cret",
	})
	cfg, err := getConfig(ctx, storage)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg.RotationPeriod != defaultRotationPeriodSeconds {
		t.Fatalf("initial rotation_period = %d, want %d (1d)", cfg.RotationPeriod, defaultRotationPeriodSeconds)
	}

	// Update omitting rotation_period must preserve the stored value.
	write(map[string]interface{}{"client_id": "admin-2"})
	cfg, _ = getConfig(ctx, storage)
	if cfg.RotationPeriod != defaultRotationPeriodSeconds {
		t.Fatalf("rotation_period changed on partial update: got %d, want %d", cfg.RotationPeriod, defaultRotationPeriodSeconds)
	}

	// Explicit 0 disables automatic rotation.
	write(map[string]interface{}{"rotation_period": 0})
	cfg, _ = getConfig(ctx, storage)
	if cfg.RotationPeriod != 0 {
		t.Fatalf("rotation_period = %d, want 0 (disabled)", cfg.RotationPeriod)
	}
}

// TestConfigIsConfigured guards the gate periodicFunc uses to skip rotation
// until the admin connection details are fully present.
func TestConfigIsConfigured(t *testing.T) {
	if (*config)(nil).isConfigured() {
		t.Error("nil config should not be configured")
	}
	if (&config{}).isConfigured() {
		t.Error("empty config should not be configured")
	}
	if (&config{ServerURL: "x", ClientID: "y"}).isConfigured() {
		t.Error("config missing client_secret should not be configured")
	}
	if !(&config{ServerURL: "x", ClientID: "y", ClientSecret: "z"}).isConfigured() {
		t.Error("fully populated config should be configured")
	}
}
