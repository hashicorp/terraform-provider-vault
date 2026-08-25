// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

const rfc2136Affix = "config/dns/rfc2136"

var rfc2136IDRe = regexp.MustCompile(`^([^/]+)/` + rfc2136Affix + `/([^/]+)$`)

var _ resource.ResourceWithConfigure = &PKIExternalCADNSProviderRFC2136Resource{}

func NewPKIExternalCADNSProviderRFC2136Resource() resource.Resource {
	return &PKIExternalCADNSProviderRFC2136Resource{}
}

type PKIExternalCADNSProviderRFC2136Resource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type PKIExternalCADNSProviderRFC2136Model struct {
	base.BaseModel

	Mount       types.String `tfsdk:"mount"`
	Name        types.String `tfsdk:"name"`
	Identifiers types.List   `tfsdk:"identifiers"`
	TTL         types.String `tfsdk:"ttl"`

	// Computed
	CreationDate    types.String `tfsdk:"creation_date"`
	LastUpdatedDate types.String `tfsdk:"last_updated_date"`

	// Provider-specific
	Nameserver    types.String `tfsdk:"nameserver"`
	TsigKeyName   types.String `tfsdk:"tsig_key_name"`
	TsigSecret    types.String `tfsdk:"tsig_secret"`
	TsigAlgorithm types.String `tfsdk:"tsig_algorithm"`
}

type PKIExternalCADNSProviderRFC2136APIModel struct {
	Name            string   `json:"name" mapstructure:"name"`
	Identifiers     []string `json:"identifiers" mapstructure:"identifiers"`
	TTL             string   `json:"ttl" mapstructure:"ttl"`
	CreationDate    string   `json:"creation_date" mapstructure:"creation_date"`
	LastUpdatedDate string   `json:"last_updated_date" mapstructure:"last_updated_date"`
	Nameserver      string   `json:"nameserver" mapstructure:"nameserver"`
	TsigKeyName     string   `json:"tsig_key_name" mapstructure:"tsig_key_name"`
	TsigAlgorithm   string   `json:"tsig_algorithm" mapstructure:"tsig_algorithm"`
}

func (r *PKIExternalCADNSProviderRFC2136Resource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_external_ca_secret_backend_dns_provider_rfc2136"
}

func (r *PKIExternalCADNSProviderRFC2136Resource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an RFC2136 DNS provider configuration for PKI External CA DNS-01 ACME challenges.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "The path where the PKI External CA secret backend is mounted.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the DNS provider configuration.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			consts.FieldIdentifiers: schema.ListAttribute{
				MarkdownDescription: "List of domain identifiers this provider handles. Supports wildcard patterns with leftmost `*` (e.g. `*.example.com`).",
				ElementType:         types.StringType,
				Required:            true,
			},
			consts.FieldTTL: schema.StringAttribute{
				MarkdownDescription: "TTL for DNS TXT records used in DNS-01 challenges. Defaults to `1m0s`.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldCreationDate: schema.StringAttribute{
				MarkdownDescription: "The date and time the provider was created.",
				Computed:            true,
			},
			consts.FieldLastUpdatedDate: schema.StringAttribute{
				MarkdownDescription: "The date and time the provider was last updated.",
				Computed:            true,
			},
			consts.FieldNameserver: schema.StringAttribute{
				MarkdownDescription: "DNS server address in `IP:port` format (e.g. `192.168.1.1:53`).",
				Optional:            true,
			},
			consts.FieldTsigKeyName: schema.StringAttribute{
				MarkdownDescription: "TSIG key name for authenticated DNS updates.",
				Optional:            true,
			},
			consts.FieldTsigSecret: schema.StringAttribute{
				MarkdownDescription: "TSIG secret (base64 encoded). Write-only — not returned by Vault.",
				Optional:            true,
				Sensitive:           true,
			},
			consts.FieldTsigAlgorithm: schema.StringAttribute{
				MarkdownDescription: "TSIG algorithm (e.g. `hmac-sha256`, `hmac-sha512`). Defaults to `hmac-sha256`.",
				Optional:            true,
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *PKIExternalCADNSProviderRFC2136Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExternalCADNSProviderRFC2136Model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := checkVaultVersionDNS(r.Meta()); err != nil {
		resp.Diagnostics.AddError("Vault Version Check Failed", err.Error())
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), rfc2136Affix, data.Name.ValueString())

	vaultReq, diags := buildRFC2136Request(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createResp, err := cli.Logical().WriteWithContext(ctx, vaultPath, vaultReq)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	resp.Diagnostics.Append(handleRFC2136Response(ctx, &data, createResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderRFC2136Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExternalCADNSProviderRFC2136Model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), rfc2136Affix, data.Name.ValueString())

	readResp, err := cli.Logical().ReadWithContext(ctx, vaultPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(handleRFC2136Response(ctx, &data, readResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderRFC2136Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PKIExternalCADNSProviderRFC2136Model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), rfc2136Affix, data.Name.ValueString())

	vaultReq, diags := buildRFC2136Request(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateResp, err := cli.Logical().WriteWithContext(ctx, vaultPath, vaultReq)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	resp.Diagnostics.Append(handleRFC2136Response(ctx, &data, updateResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderRFC2136Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PKIExternalCADNSProviderRFC2136Model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), rfc2136Affix, data.Name.ValueString())

	if _, err := cli.Logical().DeleteWithContext(ctx, vaultPath); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *PKIExternalCADNSProviderRFC2136Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := rfc2136IDRe.FindStringSubmatch(req.ID)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<mount>/%s/<name>', got: %s", rfc2136Affix, req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), matches[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), matches[2])...)
}

func buildRFC2136Request(ctx context.Context, data *PKIExternalCADNSProviderRFC2136Model) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics
	req := map[string]any{}

	if !data.TTL.IsNull() && !data.TTL.IsUnknown() {
		req[consts.FieldTTL] = data.TTL.ValueString()
	}

	var ids []string
	diags.Append(data.Identifiers.ElementsAs(ctx, &ids, false)...)
	if !diags.HasError() {
		req[consts.FieldIdentifiers] = ids
	}

	setIfNotEmpty(req, consts.FieldNameserver, data.Nameserver.ValueString())
	setIfNotEmpty(req, consts.FieldTsigKeyName, data.TsigKeyName.ValueString())
	setIfNotEmpty(req, consts.FieldTsigSecret, data.TsigSecret.ValueString())
	setIfNotEmpty(req, consts.FieldTsigAlgorithm, data.TsigAlgorithm.ValueString())

	return req, diags
}

func handleRFC2136Response(ctx context.Context, data *PKIExternalCADNSProviderRFC2136Model, readResp *api.Secret) (rd diag.Diagnostics) {
	var apiModel PKIExternalCADNSProviderRFC2136APIModel
	if err := model.ToAPIModel(readResp.Data, &apiModel); err != nil {
		rd.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.CreationDate = types.StringValue(apiModel.CreationDate)
	data.LastUpdatedDate = types.StringValue(apiModel.LastUpdatedDate)

	if apiModel.TTL != "" {
		data.TTL = types.StringValue(apiModel.TTL)
	}

	if apiModel.Identifiers != nil {
		ids, diags := types.ListValueFrom(ctx, types.StringType, apiModel.Identifiers)
		rd.Append(diags...)
		if !rd.HasError() {
			data.Identifiers = ids
		}
	}

	setStringIfNotEmpty(&data.Nameserver, apiModel.Nameserver)
	setStringIfNotEmpty(&data.TsigKeyName, apiModel.TsigKeyName)
	setStringIfNotEmpty(&data.TsigAlgorithm, apiModel.TsigAlgorithm)
	// tsig_secret intentionally not read back — write-only

	return rd
}
