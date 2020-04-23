package schema

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func NewProvider(seed *schema.Provider) *Provider {
	return &Provider{
		provider: seed,
	}
}

type Provider struct {
	provider *schema.Provider
}

func (p *Provider) RegisterDataSource(name string, dataSource *schema.Resource) {
	p.provider.DataSourcesMap[name] = dataSource
}

func (p *Provider) RegisterResource(name string, resource *schema.Resource) {
	p.provider.ResourcesMap[name] = resource
}

func (p *Provider) SchemaProvider() *schema.Provider {
	return p.provider
}

func (p *Provider) ResourceProvider() terraform.ResourceProvider {
	return p.provider
}
