// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package schema

import (
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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

func (p *Provider) GRPCProvider() tfprotov5.ProviderServer {
	return p.provider.GRPCProvider()
}

func (p *Provider) Meta() interface{} {
	return p.provider.Meta()
}
