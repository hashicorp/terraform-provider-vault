package spiffe

import (
	"context"
	"fmt"
	"regexp"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/vault/api"
)

var mintjwtNameRegexp = regexp.MustCompile("^(.+)/role/(.+)/mintjwt$")

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ ephemeral.EphemeralResource = &SpiffeSecretBackendMintJwtResource{}

// NewSpiffeSecretBackendMintJwtResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewSpiffeSecretBackendMintJwtResource() ephemeral.EphemeralResource {
	return &SpiffeSecretBackendMintJwtResource{}
}

// SpiffeSecretBackendMintJwtResource implements the methods that define this resource
type SpiffeSecretBackendMintJwtResource struct {
	base.EphemeralResourceWithConfigure
}

type SpiffeSecretBackendMintJwtModel struct {
	base.BaseModelEphemeral

	Mount    types.String `tfsdk:"mount"`
	Name     types.String `tfsdk:"name"`
	Audience types.String `tfsdk:"audience"`
	Token    types.String `tfsdk:"token"`
}

type SpiffeSecretBackendMintJwtAPIModel struct {
	Name     string `json:"name" mapstructure:"name"`
	Audience string `json:"audience" mapstructure:"audience"`
	Token    string `json:"token" mapstructure:"token"`
}

func (s *SpiffeSecretBackendMintJwtResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_spiffe_secret_backend_mintjwt"
}

func (s *SpiffeSecretBackendMintJwtResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Description: "Mount path for the SPIFFE secrets engine in Vault.",
				Required:    true,
			},
			consts.FieldName: schema.StringAttribute{
				Description: "Name of the SPIFFE role.",
				Required:    true,
			},
			"audience": schema.StringAttribute{
				Description: "The audience claim to use",
				Required:    true,
			},
			"token": schema.StringAttribute{
				Description: "The SPIFFE trust domain for this backend.",
				Computed:    true,
			},
		},
		Description: "Provides an ephemeral resource to mint a JWT-SVID.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (s *SpiffeSecretBackendMintJwtResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data SpiffeSecretBackendMintJwtModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

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

	mountPath, err := s.path(&data)
	if err != nil {
		resp.Diagnostics.AddError("Error determining role name", err.Error())
		return
	}

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

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (s *SpiffeSecretBackendMintJwtResource) path(data *SpiffeSecretBackendMintJwtModel) (string, error) {
	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	if mount == "" || name == "" {
		return "", fmt.Errorf("mount and name are required fields got mount: %q name: %q", mount, name)
	}
	return fmt.Sprintf("%s/role/%s/mintjwt", mount, name), nil
}

func (s *SpiffeSecretBackendMintJwtResource) getApiModel(_ context.Context, data *SpiffeSecretBackendMintJwtModel) (map[string]any, diag.Diagnostics) {
	apiModel := SpiffeSecretBackendMintJwtAPIModel{
		Name:     data.Name.ValueString(),
		Audience: data.Audience.ValueString(),
		Token:    data.Token.ValueString(),
	}

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode SPIFFE mintjwt API model to map", err.Error()),
		}
	}

	return vaultRequest, nil
}

func (s *SpiffeSecretBackendMintJwtResource) populateDataModelFromApi(_ context.Context, data *SpiffeSecretBackendMintJwtModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp SpiffeSecretBackendMintJwtAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}
	data.Token = types.StringValue(readResp.Token)

	return diag.Diagnostics{}
}
