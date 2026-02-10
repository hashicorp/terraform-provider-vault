// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

const roleAffix = "role"

var roleIDRe = regexp.MustCompile(`^([^/]+)/` + roleAffix + `/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &PKIExternalCARoleResource{}

// NewPKIExternalCARoleResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewPKIExternalCARoleResource() resource.Resource {
	return &PKIExternalCARoleResource{}
}

// PKIExternalCARoleResource implements the methods that define this resource
type PKIExternalCARoleResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// PKIExternalCARoleModel describes the Terraform resource data model to match the
// resource schema.
type PKIExternalCARoleModel struct {
	base.BaseModelLegacy

	Mount                   types.String `tfsdk:"mount"`
	Name                    types.String `tfsdk:"name"`
	AcmeAccountName         types.String `tfsdk:"acme_account_name"`
	AllowedDomains          types.List   `tfsdk:"allowed_domains"`
	AllowedDomainsOptions   types.List   `tfsdk:"allowed_domains_options"`
	AllowedChallengeTypes   types.List   `tfsdk:"allowed_challenge_types"`
	CsrGenerateKeyType      types.String `tfsdk:"csr_generate_key_type"`
	CsrIdentifierPopulation types.String `tfsdk:"csr_identifier_population"`
	Force                   types.Bool   `tfsdk:"force"`
	CreationDate            types.String `tfsdk:"creation_date"`
	LastUpdateDate          types.String `tfsdk:"last_update_date"`
}

// PKIExternalCARoleAPIModel describes the Vault API data model.
type PKIExternalCARoleAPIModel struct {
	Name                    string   `json:"name" mapstructure:"name"`
	AcmeAccountName         string   `json:"acme_account_name" mapstructure:"acme_account_name"`
	AllowedDomains          []string `json:"allowed_domains" mapstructure:"allowed_domains"`
	AllowedDomainsOptions   []string `json:"allowed_domains_options" mapstructure:"allowed_domains_options"`
	AllowedChallengeTypes   []string `json:"allowed_challenge_types" mapstructure:"allowed_challenge_types"`
	CsrGenerateKeyType      string   `json:"csr_generate_key_type" mapstructure:"csr_generate_key_type"`
	CsrIdentifierPopulation string   `json:"csr_identifier_population" mapstructure:"csr_identifier_population"`
	CreationDate            string   `json:"creation_date" mapstructure:"creation_date"`
	LastUpdateDate          string   `json:"last_updated_date" mapstructure:"last_updated_date"`
}

func (r *PKIExternalCARoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_secret_backend_external_ca_role"
}

func (r *PKIExternalCARoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "The path where the PKI External CA secret backend is mounted.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the role.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"acme_account_name": schema.StringAttribute{
				MarkdownDescription: "The ACME account to use when validating certificates.",
				Required:            true,
			},
			"allowed_domains": schema.ListAttribute{
				MarkdownDescription: "A list of domains the role will accept certificates for. May contain templates, as with ACL Path Templating.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"allowed_domains_options": schema.ListAttribute{
				MarkdownDescription: "A list of keyword options that influence how values within allowed_domains are interpreted against the requested set of identifiers from the client. Valid values are: `bare_domains`, `subdomains`, `wildcards`, `globs`.",
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
			},
			"allowed_challenge_types": schema.ListAttribute{
				MarkdownDescription: "The list of challenge types that are allowed to be used. Valid values are: `http-01`, `dns-01`, `tls-alpn-01`. Defaults to all challenge types.",
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				Default: listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("http-01"),
					types.StringValue("dns-01"),
					types.StringValue("tls-alpn-01"),
				})),
			},
			"csr_generate_key_type": schema.StringAttribute{
				MarkdownDescription: "The key type and size/parameters to use when generating a new key if running in the identifier workflow. Valid values are: `ec-256`, `ec-384`, `ec-521`, `rsa-2048`, `rsa-4096`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("ec-256"),
				Validators: []validator.String{
					stringvalidator.OneOf("ec-256", "ec-384", "ec-521", "rsa-2048", "rsa-4096"),
				},
			},
			"csr_identifier_population": schema.StringAttribute{
				MarkdownDescription: "The technique used to populate a CSR from the provided identifiers in the identifier workflow. Valid values are: `cn_first`, `sans_only`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("cn_first"),
				Validators: []validator.String{
					stringvalidator.OneOf("cn_first", "sans_only"),
				},
			},
			"force": schema.BoolAttribute{
				MarkdownDescription: "Force deletion even when active orders exist.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"creation_date": schema.StringAttribute{
				MarkdownDescription: "The date and time the role was created in RFC3339 format.",
				Computed:            true,
			},
			"last_update_date": schema.StringAttribute{
				MarkdownDescription: "The date and time the role was last updated in RFC3339 format.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Manage PKI External CA roles for certificate issuance via ACME.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/create
func (r *PKIExternalCARoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExternalCARoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/%s/%s", mount, roleAffix, name)

	vaultRequest, diags := buildRoleVaultRequestFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createResp, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	data.ID = types.StringValue(makeRoleID(mount, name))
	resp.Diagnostics.Append(handleRoleResponseData(ctx, &data, createResp)...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform
// refresh commands.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/read
func (r *PKIExternalCARoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExternalCARoleModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/%s/%s", mount, roleAffix, name)
	data.ID = types.StringValue(makeRoleID(mount, name))

	readResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(handleRoleResponseData(ctx, &data, readResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCARoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PKIExternalCARoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/%s/%s", mount, roleAffix, name)
	data.ID = types.StringValue(makeRoleID(mount, name))

	vaultRequest, diags := buildRoleVaultRequestFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateResp, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}
	resp.Diagnostics.Append(handleRoleResponseData(ctx, &data, updateResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func handleRoleResponseData(ctx context.Context, data *PKIExternalCARoleModel, readResp *api.Secret) (rd diag.Diagnostics) {
	var apiModel PKIExternalCARoleAPIModel
	err := model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		rd.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values back to Terraform model
	data.AcmeAccountName = types.StringValue(apiModel.AcmeAccountName)
	data.CsrGenerateKeyType = types.StringValue(apiModel.CsrGenerateKeyType)
	data.CsrIdentifierPopulation = types.StringValue(apiModel.CsrIdentifierPopulation)
	data.CreationDate = types.StringValue(apiModel.CreationDate)
	data.LastUpdateDate = types.StringValue(apiModel.LastUpdateDate)

	// Convert allowed_domains list
	if len(apiModel.AllowedDomains) > 0 {
		allowedDomainsList, diags := types.ListValueFrom(ctx, types.StringType, apiModel.AllowedDomains)
		rd.Append(diags...)
		if rd.HasError() {
			return
		}
		data.AllowedDomains = allowedDomainsList
	} else {
		data.AllowedDomains = types.ListNull(types.StringType)
	}

	// Convert allowed_domains_options list
	allowedDomainsOptionsList, diags := types.ListValueFrom(ctx, types.StringType, apiModel.AllowedDomainsOptions)
	rd.Append(diags...)
	if rd.HasError() {
		return
	}
	data.AllowedDomainsOptions = allowedDomainsOptionsList

	// Convert allowed_challenge_types list
	allowedChallengeTypesList, diags := types.ListValueFrom(ctx, types.StringType, apiModel.AllowedChallengeTypes)
	rd.Append(diags...)
	if rd.HasError() {
		return
	}
	data.AllowedChallengeTypes = allowedChallengeTypesList

	return rd
}

func buildRoleVaultRequestFromModel(ctx context.Context, data *PKIExternalCARoleModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultRequest := map[string]any{
		"acme_account_name":         data.AcmeAccountName.ValueString(),
		"csr_generate_key_type":     data.CsrGenerateKeyType.ValueString(),
		"csr_identifier_population": data.CsrIdentifierPopulation.ValueString(),
	}

	// Convert allowed_domains list to string slice
	if !data.AllowedDomains.IsNull() && !data.AllowedDomains.IsUnknown() {
		var allowedDomains []string
		if allowedDomainsDiags := data.AllowedDomains.ElementsAs(ctx, &allowedDomains, false); allowedDomainsDiags.HasError() {
			diags.Append(allowedDomainsDiags...)
			return nil, diags
		}
		vaultRequest["allowed_domains"] = allowedDomains
	}

	// Convert allowed_domains_options list to string slice
	if !data.AllowedDomainsOptions.IsNull() && !data.AllowedDomainsOptions.IsUnknown() {
		var allowedDomainsOptions []string
		if optionsDiags := data.AllowedDomainsOptions.ElementsAs(ctx, &allowedDomainsOptions, false); optionsDiags.HasError() {
			diags.Append(optionsDiags...)
			return nil, diags
		}
		vaultRequest["allowed_domains_options"] = allowedDomainsOptions
	}

	// Convert allowed_challenge_types list to string slice
	if !data.AllowedChallengeTypes.IsNull() && !data.AllowedChallengeTypes.IsUnknown() {
		var allowedChallengeTypes []string
		if challengeDiags := data.AllowedChallengeTypes.ElementsAs(ctx, &allowedChallengeTypes, false); challengeDiags.HasError() {
			diags.Append(challengeDiags...)
			return nil, diags
		}
		vaultRequest["allowed_challenge_types"] = allowedChallengeTypes
	}

	return vaultRequest, diags
}

func (r *PKIExternalCARoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PKIExternalCARoleModel

	// Load state
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/%s/%s", mount, roleAffix, name)

	// If force is set, add it as a query parameter
	params := map[string][]string{}
	if data.Force.ValueBool() {
		params["force"] = []string{"true"}
	}

	if _, err := cli.Logical().DeleteWithDataWithContext(ctx, path, params); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *PKIExternalCARoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := roleIDRe.FindStringSubmatch(req.ID)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<mount>/%s/<name>', got: %s", roleAffix, req.ID),
		)
		return
	}

	mount := matches[1]
	name := matches[2]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldID), req.ID)...)
}

func makeRoleID(mount, name string) string {
	return fmt.Sprintf("%s/%s/%s", mount, roleAffix, name)
}
