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

var backendNameRegexp = regexp.MustCompile("^(.+)/config$")

// Ensure the implementation satisfies the resource.ResourceWithImportState interface
var _ resource.ResourceWithImportState = &SpiffeSecretBackendConfigResource{}

// NewSpiffeSecretBackendConfigResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewSpiffeSecretBackendConfigResource() resource.Resource {
	return &SpiffeSecretBackendConfigResource{}
}

// SpiffeSecretBackendConfigResource implements the methods that define this resource
type SpiffeSecretBackendConfigResource struct {
	base.ResourceWithConfigure
}

type SpiffeSecretBackendConfigModel struct {
	base.BaseModel

	Mount                    types.String `tfsdk:"mount"`
	TrustDomain              types.String `tfsdk:"trust_domain"`
	BundleRefreshHint        types.String `tfsdk:"bundle_refresh_hint"`
	KeyLifetime              types.String `tfsdk:"key_lifetime"`
	JwtIssuerUrl             types.String `tfsdk:"jwt_issuer_url"`
	JwtSigningAlgorithm      types.String `tfsdk:"jwt_signing_algorithm"`
	JwtOidcCompatibilityMode types.Bool   `tfsdk:"jwt_oidc_compatibility_mode"`
}

type SpiffeSecretConfigAPIModel struct {
	TrustDomain              string `json:"trust_domain" mapstructure:"trust_domain"`
	BundleRefreshHint        string `json:"bundle_refresh_hint" mapstructure:"bundle_refresh_hint,omitempty"`
	KeyLifetime              string `json:"key_lifetime" mapstructure:"key_lifetime,omitempty"`
	JwtIssuerUrl             string `json:"jwt_issuer_url" mapstructure:"jwt_issuer_url,omitempty"`
	JwtSigningAlgorithm      string `json:"jwt_signing_algorithm" mapstructure:"jwt_signing_algorithm,omitempty"`
	JwtOidcCompatibilityMode bool   `json:"jwt_oidc_compatibility_mode" mapstructure:"jwt_oidc_compatibility_mode,omitempty"`
}

func (s *SpiffeSecretBackendConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_spiffe_secret_backend_config"
}

func (s *SpiffeSecretBackendConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Description: "Mount path for the SPIFFE secrets engine in Vault.",
				Required:    true,
			},
			"trust_domain": schema.StringAttribute{
				Description: "The SPIFFE trust domain for this backend.",
				Required:    true,
			},
			"bundle_refresh_hint": schema.StringAttribute{
				Description: "Refresh hint to use in trust bundles.",
				Optional:    true,
				Computed:    true,
			},
			"key_lifetime": schema.StringAttribute{
				Description: "How long a signing key will live for once it starts being used to sign.",
				Optional:    true,
				Computed:    true,
			},
			"jwt_issuer_url": schema.StringAttribute{
				Description: "Base URL to use for JWT iss claim.",
				Optional:    true,
				Computed:    true,
			},
			"jwt_signing_algorithm": schema.StringAttribute{
				Description: "Signing algorithm to use for JWTs.",
				Optional:    true,
				Computed:    true,
			},
			"jwt_oidc_compatibility_mode": schema.BoolAttribute{
				Description: "If true, SPIFFE IDs in JWT SVIDs must not exceed 255 bytes, the limit for the sub claim in OIDC.",
				Optional:    true,
				Computed:    true,
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (s *SpiffeSecretBackendConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SpiffeSecretBackendConfigModel

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

	vaultRequest, diagErr := s.getApiModel(ctx, &data)
	if diagErr != nil {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	mountPath := s.path(data.Mount.ValueString())
	vaultResp, err := vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}
	if vaultResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := s.populateDataModelFromApi(ctx, &data, vaultResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeSecretBackendConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SpiffeSecretBackendConfigModel
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

	vaultResp, err := vaultClient.Logical().ReadWithContext(ctx, s.path(data.Mount.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if vaultResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := s.populateDataModelFromApi(ctx, &data, vaultResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeSecretBackendConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data SpiffeSecretBackendConfigModel

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

	vaultRequest, diagErr := s.getApiModel(ctx, &data)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	mountPath := s.path(data.Mount.ValueString())
	vaultResp, err := vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}
	if vaultResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diagErr := s.populateDataModelFromApi(ctx, &data, vaultResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (s *SpiffeSecretBackendConfigResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// API does not support delete, so just remove from state
}

func (s *SpiffeSecretBackendConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (s *SpiffeSecretBackendConfigResource) path(mount string) string {
	return fmt.Sprintf("%s/%s", mount, spiffeConfigPath)
}

func (s *SpiffeSecretBackendConfigResource) getApiModel(_ context.Context, data *SpiffeSecretBackendConfigModel) (map[string]any, diag.Diagnostics) {
	apiModel := SpiffeSecretConfigAPIModel{
		TrustDomain:              data.TrustDomain.ValueString(),
		BundleRefreshHint:        data.BundleRefreshHint.ValueString(),
		KeyLifetime:              data.KeyLifetime.ValueString(),
		JwtIssuerUrl:             data.JwtIssuerUrl.ValueString(),
		JwtSigningAlgorithm:      data.JwtSigningAlgorithm.ValueString(),
		JwtOidcCompatibilityMode: data.JwtOidcCompatibilityMode.ValueBool(),
	}

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode SPIFFE config API model to map", err.Error()),
		}
	}

	return vaultRequest, nil
}

func (s *SpiffeSecretBackendConfigResource) populateDataModelFromApi(_ context.Context, data *SpiffeSecretBackendConfigModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp SpiffeSecretConfigAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}
	data.TrustDomain = types.StringValue(readResp.TrustDomain)
	data.BundleRefreshHint = types.StringValue(readResp.BundleRefreshHint)
	data.KeyLifetime = types.StringValue(readResp.KeyLifetime)

	data.JwtIssuerUrl = types.StringNull()
	if readResp.JwtIssuerUrl != "" {
		data.JwtIssuerUrl = types.StringValue(readResp.JwtIssuerUrl)
	}

	data.JwtSigningAlgorithm = types.StringValue(readResp.JwtSigningAlgorithm)
	data.JwtOidcCompatibilityMode = types.BoolValue(readResp.JwtOidcCompatibilityMode)

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
		return "", fmt.Errorf("import identifier must be of the form '<mount>/config', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	matches := backendNameRegexp.FindStringSubmatch(id)
	if len(matches) != 2 {
		return "", fmt.Errorf("import identifier must be of the form '<mount>/config', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	mount := strings.TrimSpace(matches[1])
	if mount == "" {
		return "", fmt.Errorf("mount cannot be empty")
	}

	return mount, nil
}
