package fwprovider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// Ensure the implementation satisfies the provider.Provider interface
var _ provider.Provider = &fwprovider{}

// New returns a new, initialized Terraform Plugin Framework-style provider instance.
//
// The provider instance is fully configured once the `Configure` method has been called.
func New(primary interface{ Meta() interface{} }) provider.Provider {
	return &fwprovider{
		Primary: primary,
	}
}

// Provider implements the terraform-plugin-framework's provider.Provider
// interface
//
// See: https://developer.hashicorp.com/terraform/plugin/framework
type fwprovider struct {
	Primary interface{ Meta() interface{} }
}

// Metadata returns the metadata for the provider, such as a type name and
// version data.
func (p *fwprovider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "vault"
	// TODO: inject provider version during build time
	// resp.Version = "0.0.0-dev"
}

// Schema returns the schema for this provider's configuration.
//
// Schema is called during validate, plan and apply.
func (p *fwprovider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	// TODO: must this match exactly to the SDKv2 provider's schema?
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldAddress: schema.StringAttribute{
				Required:    true,
				Description: "URL of the root of the target Vault server.",
			},
		},
	}
}

// Configure handles the configuration of any provider-level data or clients.
// These configuration values may be from the practitioner Terraform
// configuration, environment variables, or other means such as reading
// vendor-specific configuration files.
//
// Configure is called during plan and apply.
func (p *fwprovider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// Provider's parsed configuration (its instance state) is available through the primary provider's Meta() method.
	v := p.Primary.Meta()
	resp.DataSourceData = v
	resp.ResourceData = v
}

// Resources returns a slice of functions to instantiate each Resource
// implementation.
//
// The resource type name is determined by the Resource implementing
// the Metadata method. All resources must have unique names.
func (p *fwprovider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

// DataSources returns a slice of functions to instantiate each DataSource
// implementation.
//
// The data source type name is determined by the DataSource implementing
// the Metadata method. All data sources must have unique names.
func (p *fwprovider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
