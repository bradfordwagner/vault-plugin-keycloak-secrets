package backend

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestPathsCreateOperationHaveExistenceCheck enforces the Vault SDK framework
// invariant that every path registering a CreateOperation must also define an
// ExistenceCheck. The framework validates this lazily — it panics inside
// (*Backend).init on the FIRST HandleRequest, not at construction — so a plain
// `go build`/`go vet` and unit tests that never route a request through the
// framework will not catch a violation. This asserts the rule structurally at
// build time. Regression guard for config/rotate, which shipped in v0.1.0-rc1
// with a CreateOperation and no ExistenceCheck and panicked on first use.
func TestPathsCreateOperationHaveExistenceCheck(t *testing.T) {
	b := newBackend()
	for _, p := range b.Backend.Paths {
		if _, hasCreate := p.Operations[logical.CreateOperation]; hasCreate && p.ExistenceCheck == nil {
			t.Errorf("path %q registers a CreateOperation but has no ExistenceCheck; "+
				"Vault's framework panics on this at init. Either add an ExistenceCheck "+
				"or, for an action endpoint, register only UpdateOperation.", p.Pattern)
		}
	}
}
