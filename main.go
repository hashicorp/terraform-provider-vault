package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"

	"github.com/hashicorp/terraform-provider-vault/generated"
	"github.com/hashicorp/terraform-provider-vault/schema"
	"github.com/hashicorp/terraform-provider-vault/vault"
)

func main() {
	p := schema.NewProvider(vault.Provider())
	for name, resource := range generated.DataSourceRegistry {
		p.RegisterDataSource(name, vault.UpdateSchemaResource(resource))
	}
	for name, resource := range generated.ResourceRegistry {
		p.RegisterResource(name, vault.UpdateSchemaResource(resource))
	}
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: p.SchemaProvider,
	})
}
