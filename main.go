package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/terraform-providers/terraform-provider-vault/schema"
	"github.com/terraform-providers/terraform-provider-vault/vault"
)

func main() {
	p := schema.NewProvider(vault.Provider())
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: p.ResourceProvider})
}
