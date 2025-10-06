package spiffe

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
var _ resource.ResourceWithConfigure = &SpiffeAuthConfigResource{}

// NewSpiffeAuthConfigResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewSpiffeAuthConfigResource() resource.Resource {
	return &SpiffeAuthConfigResource{}
}

// SpiffeAuthConfigResource implements the methods that define this resource
type SpiffeAuthConfigResource struct {
	base.ResourceWithConfigure
}

type SpiffeAuthConfigModel struct {
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

func (s *SpiffeAuthConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_spiffe_auth_config"
}

func (s *SpiffeAuthConfigResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
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

func (s *SpiffeAuthConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SpiffeAuthConfigModel

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

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeAuthConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SpiffeAuthConfigModel
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
	policyResp, err := vaultClient.Logical().ReadWithContext(ctx, s.path(data.Mount.ValueString()))
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

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeAuthConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data SpiffeAuthConfigModel

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

func (s *SpiffeAuthConfigResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// API does not support delete, so just remove from state
}

func (s *SpiffeAuthConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldMount), req, resp)

	ns, mount, err := ExtractSpiffeConfigMountFromID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier '%s' is not valid: %s", req.ID, err.Error()),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	if ns != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}

	ns = os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(
			resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}

func (s *SpiffeAuthConfigResource) path(mount string) string {
	return fmt.Sprintf("auth/%s/%s", mount, spiffeConfigPath)
}

func getApiModel(ctx context.Context, data *SpiffeAuthConfigModel, deferBundleFetch bool) (map[string]any, diag.Diagnostics) {
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

func populateDataModelFromApi(ctx context.Context, data *SpiffeAuthConfigModel, resp *api.Secret) diag.Diagnostics {
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

func ExtractSpiffeConfigMountFromID(id string) (string, string, error) {
	if id == "" {
		return "", "", fmt.Errorf("import identifier cannot be empty")
	}
	// Trim leading slash if present
	id = strings.TrimPrefix(id, "/")

	parts := strings.Split(id, "/")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("import identifier must be of the form '<namespace>/auth/<mount>/config' or 'auth/<mount>/config'")
	}
	if parts[len(parts)-1] != "config" || parts[len(parts)-3] != "auth" {
		return "", "", fmt.Errorf("import identifier must be of the form '<namespace>/auth/<mount>/config' or 'auth/<mount>/config'")
	}
	var namespace, mount string
	if len(parts) == 3 {
		// No namespace
		mount = strings.TrimSpace(parts[1])
	} else {
		mount = strings.TrimSpace(parts[len(parts)-2])
		namespace = strings.TrimSpace(strings.Join(parts[:len(parts)-3], "/"))
		if namespace == "/" {
			namespace = ""
		}
		if namespace == "" {
			return "", "", fmt.Errorf("namespace cannot be empty if specified in import identifier")
		}
	}
	if mount == "" {
		return "", "", fmt.Errorf("mount cannot be empty")
	}
	return namespace, mount, nil
}
