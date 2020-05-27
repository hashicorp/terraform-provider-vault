package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/terraform-providers/terraform-provider-vault/generated"
	"github.com/terraform-providers/terraform-provider-vault/schema"
	"github.com/terraform-providers/terraform-provider-vault/vault"
)

func main() {
	p := schema.NewProvider(vault.Provider())
	for name, resource := range generated.DataSourceRegistry {
		p.RegisterDataSource(name, resource)
	}
	for name, resource := range generated.ResourceRegistry {
		p.RegisterResource(name, resource)
	}
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: p.ResourceProvider})
}
