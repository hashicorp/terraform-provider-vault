package spiffe

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/go-viper/mapstructure/v2"
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
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/vault/api"
)

const (
	spiffeConfigPath = "config"
)

var backendNameRegexp = regexp.MustCompile("^auth/(.+)/config$")

// Ensure the implementation satisfies the resource.ResourceWithImportState interface
var _ resource.ResourceWithImportState = &SpiffeAuthConfigResource{}

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

func (s *SpiffeAuthConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_spiffe_auth_backend_config"
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

	deferBundleFetch, diagErr := s.readDeferBundleFetchConfig(ctx, req.Config)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	vaultRequest, diagErr := s.getApiModel(ctx, &data, deferBundleFetch)
	if diagErr != nil {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// vault returns a nil response on success
	mountPath := s.path(data.Mount.ValueString())
	confResp, err := vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}
	if confResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := s.populateDataModelFromApi(ctx, &data, confResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
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

	if diagErr := s.populateDataModelFromApi(ctx, &data, policyResp); diagErr.HasError() {
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
	deferBundleFetch, diagErr := s.readDeferBundleFetchConfig(ctx, req.Config)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	vaultRequest, diagErr := s.getApiModel(ctx, &data, deferBundleFetch)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	mountPath := s.path(data.Mount.ValueString())
	confResp, err := vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}
	if confResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := s.populateDataModelFromApi(ctx, &data, confResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeAuthConfigResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// API does not support delete, so just remove from state
}

func (s *SpiffeAuthConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldMount), req, resp)

	mount, err := extractSpiffeConfigMountFromID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier '%s' is not valid: %s", req.ID, err.Error()),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
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

func (s *SpiffeAuthConfigResource) readDeferBundleFetchConfig(ctx context.Context, config tfsdk.Config) (bool, diag.Diagnostics) {
	var deferBundleFetch *bool
	if diagErr := config.GetAttribute(ctx, path.Root("defer_bundle_fetch"), &deferBundleFetch); diagErr.HasError() {
		return false, diagErr
	}
	if deferBundleFetch == nil {
		return false, diag.Diagnostics{}
	}
	return *deferBundleFetch, diag.Diagnostics{}
}

func (s *SpiffeAuthConfigResource) getApiModel(ctx context.Context, data *SpiffeAuthConfigModel, deferBundleFetch bool) (map[string]any, diag.Diagnostics) {
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
	if diagErr := data.Audience.ElementsAs(ctx, &audienceVals, false); diagErr.HasError() {
		return nil, diagErr
	}
	apiModel.Audience = audienceVals

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode SPIFFE config API model to map", err.Error()),
		}
	}

	return vaultRequest, nil
}

func (s *SpiffeAuthConfigResource) populateDataModelFromApi(ctx context.Context, data *SpiffeAuthConfigModel, resp *api.Secret) diag.Diagnostics {
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

	data.EndpointSpiffeId = types.StringNull()
	if readResp.EndpointSpiffeId != "" {
		data.EndpointSpiffeId = types.StringValue(readResp.EndpointSpiffeId)
	}

	data.EndPointUrl = types.StringNull()
	if readResp.EndPointUrl != "" {
		data.EndPointUrl = types.StringValue(readResp.EndPointUrl)
	}

	data.EndpointRootCaTrustStorePem = types.StringNull()
	if readResp.EndpointRootCaTrustStorePem != "" {
		data.EndpointRootCaTrustStorePem = types.StringValue(readResp.EndpointRootCaTrustStorePem)
	}

	data.Bundle = types.StringNull()
	if readResp.Bundle != "" {
		data.Bundle = types.StringValue(readResp.Bundle)
	}

	// Note that DeferBundleFetch influences how the API is run, and is not returned from the API endpoint

	if len(readResp.Audience) > 0 {
		aud, listErr := types.ListValueFrom(ctx, types.StringType, readResp.Audience)
		if listErr != nil {
			return listErr
		}
		data.Audience = aud
	}

	return diag.Diagnostics{}
}

// extractSpiffeConfigMountFromID extracts the mount path from the given import ID provided
// by the terraform import CLI command.
func extractSpiffeConfigMountFromID(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("import identifier cannot be empty")
	}
	// Trim leading slash if present
	id = strings.Trim(id, "/")

	if !backendNameRegexp.MatchString(id) {
		return "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/config', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	matches := backendNameRegexp.FindStringSubmatch(id)
	if len(matches) != 2 {
		return "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/config', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	mount := strings.TrimSpace(matches[1])
	if mount == "" {
		return "", fmt.Errorf("mount cannot be empty")
	}

	return mount, nil
}
