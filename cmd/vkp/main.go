// Command vkp issues, renews and revokes dynamic Keycloak client credentials
// from a vault-plugin-keycloak-secrets mount. It reads VAULT_ADDR, VAULT_TOKEN
// and the other standard VAULT_* variables like the vault CLI does.
//
//	vkp issue  -realm my-realm -role my-role [-mount keycloak]
//	vkp renew  [-increment 1h] <lease_id>
//	vkp revoke <lease_id>
//
// issue prints the credentials as JSON on stdout.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/bradfordwagner/vault-plugin-keycloak-secrets/client"
)

const usage = `usage:
  vkp issue  -realm <realm> -role <role> [-mount keycloak]
  vkp renew  [-mount keycloak] [-increment 1h] <lease_id>
  vkp revoke [-mount keycloak] <lease_id>`

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vkp:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing command\n%s", usage)
	}
	cmd, args := args[0], args[1:]

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	mount := fs.String("mount", "keycloak", "engine mount path")
	realm := fs.String("realm", "", "Keycloak realm (issue)")
	role := fs.String("role", "", "engine role name (issue)")
	increment := fs.Duration("increment", 0, "renew increment; 0 uses the role ttl (renew)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	vc, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return err
	}
	c := client.New(vc, *mount)

	switch cmd {
	case "issue":
		if *realm == "" || *role == "" {
			return fmt.Errorf("issue needs -realm and -role")
		}
		creds, err := c.Issue(ctx, *realm, *role)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(creds)
	case "renew":
		if fs.NArg() != 1 {
			return fmt.Errorf("renew needs exactly one lease_id")
		}
		d, err := c.Renew(ctx, fs.Arg(0), *increment)
		if err != nil {
			return err
		}
		fmt.Println(d.Round(time.Second))
		return nil
	case "revoke":
		if fs.NArg() != 1 {
			return fmt.Errorf("revoke needs exactly one lease_id")
		}
		return c.Revoke(ctx, fs.Arg(0))
	default:
		return fmt.Errorf("unknown command %q\n%s", cmd, usage)
	}
}
