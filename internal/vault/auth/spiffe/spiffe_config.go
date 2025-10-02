package spiffe

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

const (
	spiffeConfigPath = "config"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &SpiffeConfigResource{}

// NewSpiffeConfigResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewSpiffeConfigResource() resource.Resource {
	return &SpiffeConfigResource{}
}

// SpiffeConfigResource implements the methods that define this resource
type SpiffeConfigResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type SpiffeConfigModel struct {
	base.BaseModel

	Mount                       types.String `tfsdk:"mount"`
	TrustDomain                 types.String `tfsdk:"trust_domain"`
	Profile                     types.String `tfsdk:"profile"`
	EndPointUrl                 types.String `tfsdk:"endpoint_url"`
	EndpointSpiffeId            types.String `tfsdk:"endpoint_spiffe_id"`
	EndpointRootCaTrustStorePem types.String `tfsdk:"endpoint_root_ca_truststore_pem"`
	Bundle                      types.String `tfsdk:"bundle"`
	DeferBundleFetch            types.Bool   `tfsdk:"defer_bundle_fetch"`
	Audience                    types.List   `tfsdk:"audience"`
}

type SpiffeConfigAPIModel struct {
	TrustDomain                 string   `json:"trust_domain" mapstructure:"trust_domain"`
	Profile                     string   `json:"profile" mapstructure:"profile"`
	EndPointUrl                 string   `json:"endpoint_url" mapstructure:"endpoint_url"`
	EndpointSpiffeId            string   `json:"endpoint_spiffe_id" mapstructure:"endpoint_spiffe_id"`
	EndpointRootCaTrustStorePem string   `json:"endpoint_root_ca_truststore_pem" mapstructure:"endpoint_root_ca_truststore_pem"`
	Bundle                      string   `json:"bundle" mapstructure:"bundle"`
	DeferBundleFetch            bool     `json:"defer_bundle_fetch" mapstructure:"defer_bundle_fetch"`
	Audience                    []string `json:"audience" mapstructure:"audience"`
}

func (s *SpiffeConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_spiffe_auth_config"
}

func (s *SpiffeConfigResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the SPIFFE auth engine in Vault.",
				Required:            true,
			},
			"trust_domain": schema.StringAttribute{
				MarkdownDescription: "The SPIFFE trust domain for this backend.",
				Required:            true,
			},
			"profile": schema.StringAttribute{
				MarkdownDescription: "The mechanism to fetch or embed the trust bundle to use.",
				Required:            true,
			},
			"endpoint_url": schema.StringAttribute{
				MarkdownDescription: `The URI to be used when profile is 'https_web_bundle' or 'https_spiffe_bundle'`,
				Optional:            true,
			},
			"endpoint_spiffe_id": schema.StringAttribute{
				MarkdownDescription: `The server's SPIFFE ID to validate when profile is 'https_spiffe_bundle'`,
				Optional:            true,
			},
			"endpoint_root_ca_truststore_pem": schema.StringAttribute{
				MarkdownDescription: `PEM-encoded CA certificate(s) to validate the server reached by 'endpoint_url', if set this will override the default TLS trust store`,
				Optional:            true,
			},
			"bundle": schema.StringAttribute{
				MarkdownDescription: `When profile is 'https_spiffe_bundle', the bootstrapping bundle in SPIFFE format; when profile is 'static', either a bundle in SPIFFE format or PEM-encoded CA certificate(s)`,
				Optional:            true,
			},
			"defer_bundle_fetch": schema.BoolAttribute{
				MarkdownDescription: `Don't attempt to fetch a bundle immediately; only applies when profile != static`,
				Optional:            true,
				WriteOnly:           true,
			},
			"audience": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: `A list of audience values allowed to match claims in JWT-SVIDs`,
				Optional:            true,
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (s *SpiffeConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SpiffeConfigModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, s.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	deferBundleFetch, diagErr := readDeferBundleFetchConfig(ctx, req.Config)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	vaultRequest, diagErr := getApiModel(ctx, data, deferBundleFetch)
	if diagErr != nil {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// vault returns a nil response on success
	_, err = vaultClient.Logical().WriteWithContext(ctx, s.path(data.Mount.ValueString()), vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SpiffeConfigModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, s.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// read the name from the id field to support the import command
	path := s.path(data.Mount.ValueString())
	policyResp, err := vaultClient.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if policyResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := populateDataModelFromApi(ctx, data, policyResp); diagErr != nil {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data SpiffeConfigModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, s.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}
	deferBundleFetch, diagErr := readDeferBundleFetchConfig(ctx, req.Config)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	vaultRequest, diagErr := getApiModel(ctx, data, deferBundleFetch)
	if diagErr != nil {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// vault returns a nil response on success
	_, err = vaultClient.Logical().WriteWithContext(ctx, s.path(data.Mount.ValueString()), vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func readDeferBundleFetchConfig(ctx context.Context, config tfsdk.Config) (bool, diag.Diagnostics) {
	var deferBundleFetch *bool
	if diagErr := config.GetAttribute(ctx, path.Root("defer_bundle_fetch"), &deferBundleFetch); diagErr.HasError() {
		return false, diagErr
	}
	if deferBundleFetch == nil {
		return false, diag.Diagnostics{}
	}
	return *deferBundleFetch, diag.Diagnostics{}
}

func (s *SpiffeConfigResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// API does not support delete, so just remove from state
}

func (s *SpiffeConfigResource) path(mount string) string {
	return fmt.Sprintf("auth/%s/%s", mount, spiffeConfigPath)
}

func getApiModel(ctx context.Context, data SpiffeConfigModel, deferBundleFetch bool) (map[string]any, diag.Diagnostics) {
	// Note: defer bundle fetch is marked as write-only so it is never
	// part of the plan which the data model is built from
	apiModel := SpiffeConfigAPIModel{
		TrustDomain:                 data.TrustDomain.ValueString(),
		Profile:                     data.Profile.ValueString(),
		EndPointUrl:                 data.EndPointUrl.ValueString(),
		EndpointSpiffeId:            data.EndpointSpiffeId.ValueString(),
		EndpointRootCaTrustStorePem: data.EndpointRootCaTrustStorePem.ValueString(),
		Bundle:                      data.Bundle.ValueString(),
		DeferBundleFetch:            deferBundleFetch,
	}

	var audienceVals []string
	if err := data.Audience.ElementsAs(ctx, &audienceVals, false); err != nil {
		return nil, err
	}
	apiModel.Audience = audienceVals

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode SPIFFE API model to map", err.Error()),
		}
	}

	return vaultRequest, nil
}

func populateDataModelFromApi(ctx context.Context, data SpiffeConfigModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp SpiffeConfigAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}
	data.Profile = types.StringValue(readResp.Profile)
	data.TrustDomain = types.StringValue(readResp.TrustDomain)
	data.EndpointSpiffeId = types.StringValue(readResp.EndpointSpiffeId)
	data.EndPointUrl = types.StringValue(readResp.EndPointUrl)
	data.EndpointRootCaTrustStorePem = types.StringValue(readResp.EndpointRootCaTrustStorePem)
	data.Bundle = types.StringValue(readResp.Bundle)
	// Note that DeferBundleFetch influences how the API is run, and is not returned from the API endpoint

	var listErr diag.Diagnostics
	data.Audience, listErr = types.ListValueFrom(ctx, types.StringType, readResp.Audience)
	if listErr != nil {
		return listErr
	}

	return diag.Diagnostics{}
}
