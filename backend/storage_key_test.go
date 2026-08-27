package backend

import "testing"

func TestConfigStoragePath(t *testing.T) {
	if got, want := configStoragePath, "config"; got != want {
		t.Fatalf("configStoragePath = %q, want %q", got, want)
	}
}

func TestRolesStoragePrefix(t *testing.T) {
	if got, want := rolesStoragePrefix("master"), "realm/master/roles/"; got != want {
		t.Fatalf("rolesStoragePrefix(master) = %q, want %q", got, want)
	}
	if got, want := rolesStoragePrefix("example"), "realm/example/roles/"; got != want {
		t.Fatalf("rolesStoragePrefix(example) = %q, want %q", got, want)
	}
}
