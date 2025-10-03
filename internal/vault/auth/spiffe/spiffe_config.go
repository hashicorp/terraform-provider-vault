package spiffe

import (
	"context"
	"fmt"
	"strings"

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
	"github.com/hashicorp/vault/api"
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
	base.BaseModelLegacy

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

	base.MustAddLegacyBaseSchema(&resp.Schema)
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

	vaultRequest, diagErr := getApiModel(ctx, &data, deferBundleFetch)
	if diagErr != nil {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// vault returns a nil response on success
	mountPath := s.path(data.Mount.ValueString())
	_, err = vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	data.ID = types.StringValue(mountPath)

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
	policyResp, err := vaultClient.Logical().ReadWithContext(ctx, data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if policyResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := populateDataModelFromApi(ctx, &data, policyResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	if data.Mount.IsNull() && !data.ID.IsNull() {
		// Import scenario, extract mount from ID
		mount := strings.TrimPrefix(data.ID.ValueString(), "auth/")
		mount = strings.TrimSuffix(mount, "/config")
		data.Mount = types.StringValue(mount)
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

	vaultRequest, diagErr := getApiModel(ctx, &data, deferBundleFetch)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// vault returns a nil response on success
	mountPath := s.path(data.Mount.ValueString())
	_, err = vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	data.ID = types.StringValue(mountPath)

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

func getApiModel(ctx context.Context, data *SpiffeConfigModel, deferBundleFetch bool) (map[string]any, diag.Diagnostics) {
	// Note: defer bundle fetch is marked as write-only so it is never
	// part of the plan which the data model is built from
	vaultRequest := map[string]any{
		"trust_domain":       data.TrustDomain.ValueString(),
		"profile":            data.Profile.ValueString(),
		"defer_bundle_fetch": deferBundleFetch,
	}
	if !data.EndPointUrl.IsUnknown() {
		vaultRequest["endpoint_url"] = data.EndPointUrl.ValueString()
	}
	if !data.EndpointSpiffeId.IsUnknown() {
		vaultRequest["endpoint_spiffe_id"] = data.EndpointSpiffeId.ValueString()
	}
	if !data.EndpointRootCaTrustStorePem.IsUnknown() {
		vaultRequest["endpoint_root_ca_trust_store_pem"] = data.EndpointRootCaTrustStorePem.ValueString()
	}
	if !data.Bundle.IsUnknown() {
		vaultRequest["bundle"] = data.Bundle.ValueString()
	}
	if !data.Audience.IsUnknown() {
		var audienceVals []string
		if err := data.Audience.ElementsAs(ctx, &audienceVals, false); err != nil {
			return nil, err
		}
		vaultRequest["audience"] = audienceVals
	}

	return vaultRequest, nil
}

func populateDataModelFromApi(ctx context.Context, data *SpiffeConfigModel, resp *api.Secret) diag.Diagnostics {
	var diags diag.Diagnostics

	if resp == nil || resp.Data == nil {
		diags.AddError("Missing data in API response", "The API response or response data was nil.")
		return diags
	}
	respData := resp.Data
	data.Profile = types.StringValue(respData["profile"].(string))
	data.TrustDomain = types.StringValue(respData["trust_domain"].(string))

	if v, ok := respData["endpoint_spiffe_id"]; ok {
		data.EndpointSpiffeId = types.StringValue(v.(string))
	}
	if v, ok := respData["endpoint_url"]; ok {
		data.EndPointUrl = types.StringValue(v.(string))
	}
	if v, ok := respData["endpoint_root_ca_truststore_pem"]; ok {
		data.EndpointRootCaTrustStorePem = types.StringValue(v.(string))
	}
	if v, ok := respData["bundle"]; ok {
		data.Bundle = types.StringValue(v.(string))
	}
	if v, ok := respData["audience"]; ok {
		var listErr diag.Diagnostics
		data.Audience, listErr = types.ListValueFrom(ctx, types.StringType, v)
		if listErr != nil {
			diags.Append(listErr...)
		}
	}

	return diags
}
