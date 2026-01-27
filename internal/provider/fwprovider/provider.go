// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	ephemeralauth "github.com/hashicorp/terraform-provider-vault/internal/vault/auth/ephemeral"
	"github.com/hashicorp/terraform-provider-vault/internal/vault/auth/spiffe"
	"github.com/hashicorp/terraform-provider-vault/internal/vault/secrets/azure"
	ephemeralsecrets "github.com/hashicorp/terraform-provider-vault/internal/vault/secrets/ephemeral"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	sdkv2provider "github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/vault/sys"
)

var _ provider.ProviderWithEphemeralResources = &fwprovider{}

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
	// This schema must match exactly to the SDKv2 provider's schema
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			// Not `Required` but must be set via config or env. Otherwise we
			// return an error.
			consts.FieldAddress: schema.StringAttribute{
				Optional:    true,
				Description: "URL of the root of the target Vault server.",
			},
			"add_address_to_env": schema.StringAttribute{
				Optional:    true,
				Description: "If true, adds the value of the `address` argument to the Terraform process environment.",
			},
			// Not `Required` but must be set via config, env, or token helper.
			// Otherwise we return an error.
			"token": schema.StringAttribute{
				Optional:    true,
				Description: "Token to use to authenticate to Vault.",
			},
			"token_name": schema.StringAttribute{
				Optional:    true,
				Description: "Token name to use for creating the Vault child token.",
			},
			"skip_child_token": schema.BoolAttribute{
				Optional: true,

				// Setting to true will cause max_lease_ttl_seconds and token_name to be ignored (not used).
				// Note that this is strongly discouraged due to the potential of exposing sensitive secret data.
				Description: "Set this to true to prevent the creation of ephemeral child token used by this provider.",
			},
			consts.FieldCACertFile: schema.StringAttribute{
				Optional:    true,
				Description: "Path to a CA certificate file to validate the server's certificate.",
			},
			consts.FieldCACertDir: schema.StringAttribute{
				Optional:    true,
				Description: "Path to directory containing CA certificate files to validate the server's certificate.",
			},
			consts.FieldSkipTLSVerify: schema.BoolAttribute{
				Optional:    true,
				Description: "Set this to true only if the target Vault server is an insecure development instance.",
			},
			consts.FieldTLSServerName: schema.StringAttribute{
				Optional:    true,
				Description: "Name to use as the SNI host when connecting via TLS.",
			},
			"max_lease_ttl_seconds": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum TTL for secret leases requested by this provider.",
			},
			"max_retries": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of retries when a 5xx error code is encountered.",
			},
			"max_retries_ccc": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of retries for Client Controlled Consistency related operations",
			},
			consts.FieldNamespace: schema.StringAttribute{
				Optional:    true,
				Description: "The namespace to use. Available only for Vault Enterprise.",
			},
			consts.FieldSkipGetVaultVersion: schema.BoolAttribute{
				Optional:    true,
				Description: "Skip the dynamic fetching of the Vault server version.",
			},
			consts.FieldVaultVersionOverride: schema.StringAttribute{
				Optional: true,
				Description: "Override the Vault server version, " +
					"which is normally determined dynamically from the target Vault server",
				Validators: []validator.String{
					// https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`),
						"must be a valid semantic version",
					),
				},
			},
			consts.FieldSetNamespaceFromToken: schema.BoolAttribute{
				Optional: true,
				Description: "In the case where the Vault token is for a specific namespace " +
					"and the provider namespace is not configured, use the token namespace " +
					"as the root namespace for all resources.",
			},
		},
		Blocks: map[string]schema.Block{
			"headers": schema.ListNestedBlock{
				Description: "The headers to send with each Vault request.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required:    true,
							Sensitive:   true,
							Description: "The header name",
						},
						"value": schema.StringAttribute{
							Required:    true,
							Sensitive:   true,
							Description: "The header value",
						},
					},
				},
			},
			consts.FieldClientAuth: schema.ListNestedBlock{
				Description: "Client authentication credentials.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						consts.FieldCertFile: schema.StringAttribute{
							Required:    true,
							Description: "Path to a file containing the client certificate.",
						},
						consts.FieldKeyFile: schema.StringAttribute{
							Required:    true,
							Description: "Path to a file containing the private key that the certificate was issued for.",
						},
					},
				},
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
			},
			consts.FieldAuthLoginAWS:       AuthLoginAWSSchema(),
			consts.FieldAuthLoginAzure:     AuthLoginAzureSchema(),
			consts.FieldAuthLoginCert:      AuthLoginCertSchema(),
			consts.FieldAuthLoginGCP:       AuthLoginGCPSchema(),
			consts.FieldAuthLoginGeneric:   AuthLoginGenericSchema(),
			consts.FieldAuthLoginJWT:       AuthLoginJWTSchema(),
			consts.FieldAuthLoginKerberos:  AuthLoginKerberosSchema(),
			consts.FieldAuthLoginOCI:       AuthLoginOCISchema(),
			consts.FieldAuthLoginOIDC:      AuthLoginOIDCSchema(),
			consts.FieldAuthLoginRadius:    AuthLoginRadiusSchema(),
			consts.FieldAuthLoginTokenFile: AuthLoginTokenFileSchema(),
			consts.FieldAuthLoginUserpass:  AuthLoginUserpassSchema(),
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
	// Provider's parsed configuration (its instance state) is available
	// through the primary provider's Meta() method.
	v, ok := p.Primary.Meta().(*sdkv2provider.ProviderMeta)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *provider.ProviderMeta, got: %T. Please report this issue to the provider developers.", p.Primary.Meta()),
		)
		return
	}
	resp.DataSourceData = v
	resp.ResourceData = v
	resp.EphemeralResourceData = v
}

// Resources returns a slice of functions to instantiate each Resource
// implementation.
//
// The resource type name is determined by the Resource implementing
// the Metadata method. All resources must have unique names.
func (p *fwprovider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		spiffe.NewSpiffeAuthConfigResource,
		spiffe.NewSpiffeAuthRoleResource,
		sys.NewPasswordPolicyResource,
		azure.NewAzureStaticRoleResource,
	}
}

func (p *fwprovider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		ephemeralsecrets.NewKVV2EphemeralSecretResource,
		ephemeralsecrets.NewDBEphemeralSecretResource,
		ephemeralsecrets.NewAzureStaticCredsEphemeralSecretResource,
		ephemeralsecrets.NewAzureAccessCredentialsEphemeralResource,
		ephemeralsecrets.NewGCPServiceAccountKeyEphemeralResource,
		ephemeralsecrets.NewGCPOAuth2AccessTokenEphemeralResource,
		ephemeralsecrets.NewAWSAccessCredentialsEphemeralSecretResource,
		ephemeralsecrets.NewAWSStaticAccessCredentialsEphemeralSecretResource,
		ephemeralauth.NewApproleAuthBackendRoleSecretIDEphemeralResource,
		ephemeralsecrets.NewKubernetesServiceAccountTokenEphemeralResource,
	}

}

// DataSources returns a slice of functions to instantiate each DataSource
// implementation.
//
// The data source type name is determined by the DataSource implementing
// the Metadata method. All data sources must have unique names.
func (p *fwprovider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
