package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/terraform-providers/terraform-provider-vault/generated"
	"github.com/terraform-providers/terraform-provider-vault/provider"
	"github.com/terraform-providers/terraform-provider-vault/vault"
)

func main() {
	p := provider.NewProvider(vault.Provider())
	for name, resource := range generated.ResourceRegistry {
		p.RegisterResource(name, resource)
	}
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: p.ResourceProvider})
}
