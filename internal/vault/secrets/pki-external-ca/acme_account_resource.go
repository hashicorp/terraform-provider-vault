// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
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

const acmeAccountAffix = "config/acme-account"

var acmeAccountIDRe = regexp.MustCompile(`^([^/]+)/` + acmeAccountAffix + `/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &PKIACMEAccountResource{}

// NewPKIACMEAccountResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewPKIACMEAccountResource() resource.Resource {
	return &PKIACMEAccountResource{}
}

// PKIACMEAccountResource implements the methods that define this resource
type PKIACMEAccountResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// PKIACMEAccountModel describes the Terraform resource data model to match the
// resource schema.
type PKIACMEAccountModel struct {
	base.BaseModelLegacy

	Backend          types.String `tfsdk:"backend"`
	Name             types.String `tfsdk:"name"`
	DirectoryURL     types.String `tfsdk:"directory_url"`
	EmailContacts    types.List   `tfsdk:"email_contacts"`
	KeyType          types.String `tfsdk:"key_type"`
	EABKid           types.String `tfsdk:"eab_kid"`
	EABKey           types.String `tfsdk:"eab_key"`
	Force            types.Bool   `tfsdk:"force"`
	TrustedCA        types.String `tfsdk:"trusted_ca"`
	ActiveKeyVersion types.Int64  `tfsdk:"active_key_version"`
}
type ACMEAccountKeyAPIModel struct {
	KeyType         string    `json:"key_type"`
	KeyVersion      int       `json:"key_version"`
	KeyCreationDate time.Time `json:"key_creation_date"`
}

// PKIACMEAccountAPIModel describes the Vault API data model.
type PKIACMEAccountAPIModel struct {
	DirectoryURL     string                         `json:"directory_url" mapstructure:"directory_url"`
	EmailContacts    []string                       `json:"email_contacts" mapstructure:"email_contacts"`
	KeyType          string                         `json:"key_type" mapstructure:"key_type"`
	EABKid           string                         `json:"eab_kid,omitempty" mapstructure:"eab_kid"`
	EABKey           string                         `json:"eab_key,omitempty" mapstructure:"eab_key"`
	TrustedCA        string                         `json:"trusted_ca,omitempty" mapstructure:"trusted_ca"`
	AccountKeys      map[int]ACMEAccountKeyAPIModel `json:"account_keys" mapstructure:"account_keys"`
	ActiveKeyVersion int                            `json:"active_key_version" mapstructure:"active_key_version"`
}

func (r *PKIACMEAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_secret_backend_acme_account"
}

func (r *PKIACMEAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "The path where the PKI secret backend is mounted.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the ACME account.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"directory_url": schema.StringAttribute{
				MarkdownDescription: "ACME Directory URL.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"email_contacts": schema.ListAttribute{
				MarkdownDescription: "Email addresses for the ACME account.",
				ElementType:         types.StringType,
				Required:            true,
				PlanModifiers:       []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"key_type": schema.StringAttribute{
				MarkdownDescription: "Key type to generate for the account key. Valid values are `ec-256`, `ec-384`, `rsa-2048`, `rsa-4096`, `rsa-8192`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("ec-256"),
				Validators: []validator.String{
					stringvalidator.OneOf("ec-256", "ec-384", "rsa-2048", "rsa-4096", "rsa-8192"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"eab_kid": schema.StringAttribute{
				MarkdownDescription: "The external binding key ID to create the initial account.",
				Optional:            true,
				Sensitive:           true,
				WriteOnly:           true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"eab_key": schema.StringAttribute{
				MarkdownDescription: "The external binding token to create the initial account.",
				Optional:            true,
				Sensitive:           true,
				WriteOnly:           true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"force": schema.BoolAttribute{
				MarkdownDescription: "Force the deletion of an account if orders are still pending.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"trusted_ca": schema.StringAttribute{
				MarkdownDescription: "Trusted CA certificates for the ACME server.",
				Optional:            true,
			},
			"active_key_version": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Version of account key, starts at zero",
			},
		},
		MarkdownDescription: "Manage PKI ACME accounts for external CA integration.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/create
func (r *PKIACMEAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIACMEAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/%s/%s", backend, acmeAccountAffix, name)

	vaultRequest, diags := buildVaultRequestFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createResp, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	data.ID = types.StringValue(makeACMEAccountID(backend, name))
	resp.Diagnostics.Append(handleAccountResponseData(ctx, &data, createResp)...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform
// refresh commands.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/read
func (r *PKIACMEAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIACMEAccountModel
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

	backend := data.Backend.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/%s/%s", backend, acmeAccountAffix, name)
	data.ID = types.StringValue(makeACMEAccountID(backend, name))

	readResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(handleAccountResponseData(ctx, &data, readResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIACMEAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PKIACMEAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/%s/%s", backend, acmeAccountAffix, name)
	data.ID = types.StringValue(makeACMEAccountID(backend, name))

	vaultRequest, diags := buildVaultRequestFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateResp, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}
	resp.Diagnostics.Append(handleAccountResponseData(ctx, &data, updateResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func handleAccountResponseData(ctx context.Context, data *PKIACMEAccountModel, readResp *api.Secret) (rd diag.Diagnostics) {
	var apiModel PKIACMEAccountAPIModel
	err := model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		rd.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values back to Terraform model
	data.DirectoryURL = types.StringValue(apiModel.DirectoryURL)
	data.KeyType = types.StringValue(apiModel.AccountKeys[apiModel.ActiveKeyVersion].KeyType)
	data.ActiveKeyVersion = types.Int64Value(int64(apiModel.ActiveKeyVersion))

	emailList, diags := types.ListValueFrom(ctx, types.StringType, apiModel.EmailContacts)
	rd.Append(diags...)
	if rd.HasError() {
		return
	}
	data.EmailContacts = emailList

	// Optional fields - only set if present in response
	if apiModel.TrustedCA != "" {
		data.TrustedCA = types.StringValue(apiModel.TrustedCA)
	}

	// Note: EAB credentials are write-only and won't be returned by the API
	// Keep the values from state if they were set

	return rd
}

func buildVaultRequestFromModel(ctx context.Context, data *PKIACMEAccountModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultRequest := map[string]any{
		"directory_url": data.DirectoryURL.ValueString(),
		"key_type":      data.KeyType.ValueString(),
	}

	// Convert email_contacts list to string slice
	var emailContacts []string
	if !data.EmailContacts.IsNull() && !data.EmailContacts.IsUnknown() {
		if emailDiags := data.EmailContacts.ElementsAs(ctx, &emailContacts, false); emailDiags.HasError() {
			diags.Append(emailDiags...)
			return nil, diags
		}
		vaultRequest["email_contacts"] = emailContacts
	}

	// Optional fields
	if !data.EABKid.IsNull() && !data.EABKid.IsUnknown() && data.EABKid.ValueString() != "" {
		vaultRequest["eab_kid"] = data.EABKid.ValueString()
	}

	if !data.EABKey.IsNull() && !data.EABKey.IsUnknown() && data.EABKey.ValueString() != "" {
		vaultRequest["eab_key"] = data.EABKey.ValueString()
	}

	if !data.TrustedCA.IsNull() && !data.TrustedCA.IsUnknown() && data.TrustedCA.ValueString() != "" {
		vaultRequest["trusted_ca"] = data.TrustedCA.ValueString()
	}

	return vaultRequest, diags
}

func (r *PKIACMEAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PKIACMEAccountModel

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

	backend := data.Backend.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/%s/%s", backend, acmeAccountAffix, name)

	// If force is set, add it as a query parameter
	if data.Force.ValueBool() {
		path = fmt.Sprintf("%s?force=true", path)
	}

	if _, err := cli.Logical().DeleteWithContext(ctx, path); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *PKIACMEAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := acmeAccountIDRe.FindStringSubmatch(req.ID)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<backend>/%s/<name>', got: %s", acmeAccountAffix, req.ID),
		)
		return
	}

	backend := matches[1]
	name := matches[2]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldBackend), backend)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldID), req.ID)...)
}

func makeACMEAccountID(backend, name string) string {
	return fmt.Sprintf("%s/%s/%s", backend, acmeAccountAffix, name)
}
