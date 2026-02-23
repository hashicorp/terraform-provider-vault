// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var idRe = regexp.MustCompile(`^([^/]+)/listener/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &KMIPListenerResource{}

// NewKMIPListenerResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewKMIPListenerResource() resource.Resource { return &KMIPListenerResource{} }

// KMIPListenerResource implements the methods that define this resource
type KMIPListenerResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// KMIPListenerModel describes the Terraform resource data model to match the
// resource schema.
type KMIPListenerModel struct {
	base.BaseModel

	Path                types.String `tfsdk:"path"`
	Name                types.String `tfsdk:"name"`
	CA                  types.String `tfsdk:"ca"`
	Address             types.String `tfsdk:"address"`
	AdditionalClientCAs types.List   `tfsdk:"additional_client_cas"`
	AlsoUseLegacyCA     types.Bool   `tfsdk:"also_use_legacy_ca"`
	ServerIPs           types.List   `tfsdk:"server_ips"`
	ServerHostnames     types.List   `tfsdk:"server_hostnames"`
	TLSMinVersion       types.String `tfsdk:"tls_min_version"`
	TLSMaxVersion       types.String `tfsdk:"tls_max_version"`
	TLSCipherSuites     types.String `tfsdk:"tls_cipher_suites"`
}

// KMIPListenerAPIModel describes the Vault API data model.
type KMIPListenerAPIModel struct {
	CA                  string   `json:"ca" mapstructure:"ca"`
	Address             string   `json:"address" mapstructure:"address"`
	AdditionalClientCAs []string `json:"additional_client_cas" mapstructure:"additional_client_cas"`
	AlsoUseLegacyCA     bool     `json:"also_use_legacy_ca" mapstructure:"also_use_legacy_ca"`
	ServerIPs           []string `json:"server_ips" mapstructure:"server_ips"`
	ServerHostnames     []string `json:"server_hostnames" mapstructure:"server_hostnames"`
	TLSMinVersion       string   `json:"tls_min_version" mapstructure:"tls_min_version"`
	TLSMaxVersion       string   `json:"tls_max_version" mapstructure:"tls_max_version"`
	TLSCipherSuites     string   `json:"tls_cipher_suites" mapstructure:"tls_cipher_suites"`
}

func (r *KMIPListenerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kmip_secret_listener"
}

func (r *KMIPListenerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				MarkdownDescription: "Path where KMIP backend is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Unique name for the listener.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ca": schema.StringAttribute{
				MarkdownDescription: "Name of the CA to use to generate the server certificate and verify client certificates.",
				Required:            true,
			},
			"address": schema.StringAttribute{
				MarkdownDescription: "Host:port address to listen on.",
				Required:            true,
			},
			"additional_client_cas": schema.ListAttribute{
				MarkdownDescription: "Names of additional TLS CAs to use to verify client certificates.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"also_use_legacy_ca": schema.BoolAttribute{
				MarkdownDescription: "Use the legacy unnamed CA for verifying client certificates as well.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"server_ips": schema.ListAttribute{
				MarkdownDescription: "IP SANs to include in listener certificate.",
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
			},
			"server_hostnames": schema.ListAttribute{
				MarkdownDescription: "DNS SANs to include in listener certificate.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"tls_min_version": schema.StringAttribute{
				MarkdownDescription: "Minimum TLS version to accept (tls12 or tls13).",
				Optional:            true,
				Computed:            true,
			},
			"tls_max_version": schema.StringAttribute{
				MarkdownDescription: "Maximum TLS version to accept (tls12 or tls13).",
				Optional:            true,
			},
			"tls_cipher_suites": schema.StringAttribute{
				MarkdownDescription: "TLS cipher suites to allow (does not apply to tls13+).",
				Optional:            true,
			},
		},
		MarkdownDescription: "Manage KMIP secret engine listeners.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

// readListenerFromVault reads the listener configuration from Vault and populates the model
func (r *KMIPListenerResource) readListenerFromVault(ctx context.Context, cli *api.Client, data *KMIPListenerModel, diags *diag.Diagnostics) {
	backend := data.Path.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/listener/%s", backend, name)

	readResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		diags.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiModel KMIPListenerAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values back to Terraform model
	data.CA = types.StringValue(apiModel.CA)
	data.Address = types.StringValue(apiModel.Address)
	data.AlsoUseLegacyCA = types.BoolValue(apiModel.AlsoUseLegacyCA)

	if apiModel.TLSMinVersion != "" {
		data.TLSMinVersion = types.StringValue(apiModel.TLSMinVersion)
	}
	if apiModel.TLSMaxVersion != "" {
		data.TLSMaxVersion = types.StringValue(apiModel.TLSMaxVersion)
	}
	if apiModel.TLSCipherSuites != "" {
		data.TLSCipherSuites = types.StringValue(apiModel.TLSCipherSuites)
	}

	// Set additional_client_cas if it has values or was set in config
	if len(apiModel.AdditionalClientCAs) > 0 || !data.AdditionalClientCAs.IsNull() {
		additionalCAsVal, additionalCAsDiags := types.ListValueFrom(ctx, types.StringType, apiModel.AdditionalClientCAs)
		diags.Append(additionalCAsDiags...)
		if !diags.HasError() {
			data.AdditionalClientCAs = additionalCAsVal
		}
	}

	// Set server_ips if it has values or was set in config
	if len(apiModel.ServerIPs) > 0 || !data.ServerIPs.IsNull() {
		serverIPsVal, serverIPsDiags := types.ListValueFrom(ctx, types.StringType, apiModel.ServerIPs)
		diags.Append(serverIPsDiags...)
		if !diags.HasError() {
			data.ServerIPs = serverIPsVal
		}
	}

	// Set server_hostnames if it has values or was set in config
	if len(apiModel.ServerHostnames) > 0 || !data.ServerHostnames.IsNull() {
		serverHostnamesVal, serverHostnamesDiags := types.ListValueFrom(ctx, types.StringType, apiModel.ServerHostnames)
		diags.Append(serverHostnamesDiags...)
		if !diags.HasError() {
			data.ServerHostnames = serverHostnamesVal
		}
	}
}

// Create is called during the terraform apply command.
func (r *KMIPListenerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KMIPListenerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Check if Vault version supports named listeners (requires 2.0.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion200) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			"Named KMIP listeners require Vault version 2.0.0 or later. "+
				"Current Vault version: "+r.Meta().GetVaultVersion().String(),
		)
		return
	}

	backend := data.Path.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/listener/%s", backend, name)

	vaultRequest, diags := buildVaultRequestFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Read back the response to populate computed fields
	r.readListenerFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *KMIPListenerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KMIPListenerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.readListenerFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KMIPListenerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data KMIPListenerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Path.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/listener/%s", backend, name)

	vaultRequest, diags := buildVaultRequestFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	// Read back the response to populate computed fields
	r.readListenerFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func buildVaultRequestFromModel(ctx context.Context, data *KMIPListenerModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultRequest := map[string]any{
		"ca":                 data.CA.ValueString(),
		"address":            data.Address.ValueString(),
		"also_use_legacy_ca": data.AlsoUseLegacyCA.ValueBool(),
	}

	if !data.TLSMinVersion.IsNull() && !data.TLSMinVersion.IsUnknown() {
		vaultRequest["tls_min_version"] = data.TLSMinVersion.ValueString()
	}

	if !data.TLSMaxVersion.IsNull() && !data.TLSMaxVersion.IsUnknown() {
		vaultRequest["tls_max_version"] = data.TLSMaxVersion.ValueString()
	}

	if !data.TLSCipherSuites.IsNull() && !data.TLSCipherSuites.IsUnknown() {
		vaultRequest["tls_cipher_suites"] = data.TLSCipherSuites.ValueString()
	}

	if !data.AdditionalClientCAs.IsNull() && !data.AdditionalClientCAs.IsUnknown() {
		var cas []string
		if listDiags := data.AdditionalClientCAs.ElementsAs(ctx, &cas, false); listDiags.HasError() {
			diags.Append(listDiags...)
			return nil, diags
		}
		vaultRequest["additional_client_cas"] = cas
	}

	if !data.ServerIPs.IsNull() && !data.ServerIPs.IsUnknown() {
		var ips []string
		if listDiags := data.ServerIPs.ElementsAs(ctx, &ips, false); listDiags.HasError() {
			diags.Append(listDiags...)
			return nil, diags
		}
		vaultRequest["server_ips"] = ips
	}

	if !data.ServerHostnames.IsNull() && !data.ServerHostnames.IsUnknown() {
		var hostnames []string
		if listDiags := data.ServerHostnames.ElementsAs(ctx, &hostnames, false); listDiags.HasError() {
			diags.Append(listDiags...)
			return nil, diags
		}
		vaultRequest["server_hostnames"] = hostnames
	}

	return vaultRequest, diags
}

func (r *KMIPListenerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KMIPListenerModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Path.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/listener/%s", backend, name)

	if _, err := cli.Logical().DeleteWithContext(ctx, path); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *KMIPListenerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	matches := idRe.FindStringSubmatch(id)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			fmt.Sprintf("Expected ID in format '<backend>/listener/<name>', got: %q", id),
		)
		return
	}

	backend := matches[1]
	name := matches[2]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldPath), backend)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)
}

// Made with Bob
