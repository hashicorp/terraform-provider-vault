package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/terraform-providers/terraform-provider-vault/provider"
	"github.com/terraform-providers/terraform-provider-vault/vault"
)

func main() {
	p := provider.New(vault.Provider())
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: p.ResourceProvider})
}
