// Command vault-plugin-keycloak-secrets is the entrypoint for the Keycloak
// dynamic-client secrets engine. Vault execs this binary and speaks to it over
// the plugin gRPC transport; ServeMultiplex lets a single process back multiple
// mounts.
package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	keycloak "github.com/bradfordwagner/vault-plugin-keycloak-secrets/backend"
)

// Populated by GoReleaser ldflags; harmless defaults for `go build`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("failed to parse plugin flags", "error", err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: keycloak.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "version", version, "commit", commit, "error", err)
		os.Exit(1)
	}
}
