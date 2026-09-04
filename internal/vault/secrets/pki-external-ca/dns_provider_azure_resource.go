// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"regexp"
	"time"

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

const azureAffix = "config/dns/azure-dns"

var azureIDRe = regexp.MustCompile(`^(.+)/` + azureAffix + `/([^/]+)$`)

var _ resource.ResourceWithConfigure = &PKIExternalCADNSProviderAzureResource{}

func NewPKIExternalCADNSProviderAzureResource() resource.Resource {
	return &PKIExternalCADNSProviderAzureResource{}
}

type PKIExternalCADNSProviderAzureResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type PKIExternalCADNSProviderAzureModel struct {
	base.BaseModel

	Mount       types.String `tfsdk:"mount"`
	Name        types.String `tfsdk:"name"`
	Identifiers types.List   `tfsdk:"identifiers"`
	TTL         types.Int64  `tfsdk:"ttl"`

	// Computed
	CreationDate    types.String `tfsdk:"creation_date"`
	LastUpdatedDate types.String `tfsdk:"last_updated_date"`

	// Provider-specific
	ZoneName              types.String `tfsdk:"zone_name"`
	ClientID              types.String `tfsdk:"client_id"`
	ClientSecretWO        types.String `tfsdk:"client_secret_wo"`
	ClientSecretWOVersion types.Int64  `tfsdk:"client_secret_wo_version"`
	TenantID              types.String `tfsdk:"tenant_id"`
	SubscriptionID        types.String `tfsdk:"subscription_id"`
	ResourceGroupName     types.String `tfsdk:"resource_group_name"`
	Environment           types.String `tfsdk:"environment"`
	Nameserver            types.String `tfsdk:"nameserver"`
}

type PKIExternalCADNSProviderAzureAPIModel struct {
	Name              string   `json:"name" mapstructure:"name"`
	Identifiers       []string `json:"identifiers" mapstructure:"identifiers"`
	TTL               string   `json:"ttl" mapstructure:"ttl"`
	CreationDate      string   `json:"creation_date" mapstructure:"creation_date"`
	LastUpdatedDate   string   `json:"last_updated_date" mapstructure:"last_updated_date"`
	ZoneName          string   `json:"zone_name" mapstructure:"zone_name"`
	ClientID          string   `json:"client_id" mapstructure:"client_id"`
	TenantID          string   `json:"tenant_id" mapstructure:"tenant_id"`
	SubscriptionID    string   `json:"subscription_id" mapstructure:"subscription_id"`
	ResourceGroupName string   `json:"resource_group_name" mapstructure:"resource_group_name"`
	Environment       string   `json:"environment" mapstructure:"environment"`
	Nameserver        string   `json:"nameserver" mapstructure:"nameserver"`
}

func (r *PKIExternalCADNSProviderAzureResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_external_ca_secret_backend_dns_provider_azure"
}

func (r *PKIExternalCADNSProviderAzureResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an Azure DNS provider configuration for PKI External CA DNS-01 ACME challenges.",
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
			consts.FieldTTL: schema.Int64Attribute{
				MarkdownDescription: "TTL for DNS TXT records used in DNS-01 challenges in seconds. Defaults to `60`.",
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
			consts.FieldZoneName: schema.StringAttribute{
				MarkdownDescription: "Azure DNS zone name.",
				Optional:            true,
			},
			consts.FieldClientID: schema.StringAttribute{
				MarkdownDescription: "Azure service principal client ID.",
				Optional:            true,
			},
			consts.FieldClientSecretWO: schema.StringAttribute{
					MarkdownDescription: "Azure service principal client secret. Write-only — not returned by Vault.",
					Optional:            true,
					WriteOnly:           true,
				},
			consts.FieldClientSecretWOVersion: schema.Int64Attribute{
				MarkdownDescription: "Version counter for the write-only `client_secret` field. Increment this value to trigger an update to the client secret in Vault.",
				Optional:            true,
			},
			consts.FieldTenantID: schema.StringAttribute{
				MarkdownDescription: "Azure tenant ID.",
				Optional:            true,
			},
			consts.FieldSubscriptionID: schema.StringAttribute{
				MarkdownDescription: "Azure subscription ID.",
				Optional:            true,
			},
			consts.FieldResourceGroupName: schema.StringAttribute{
				MarkdownDescription: "Resource group containing the DNS zone.",
				Optional:            true,
			},
			consts.FieldEnvironment: schema.StringAttribute{
				MarkdownDescription: "Azure cloud environment. Valid values: `AzurePublic`, `AzureChina`, `AzureGovernment`. Defaults to `AzurePublic`.",
				Optional:            true,
			},
			consts.FieldNameserver: schema.StringAttribute{
				MarkdownDescription: "Address of a DNS nameserver (`host` or `host:port`) to use when verifying DNS-01 challenge propagation instead of the domain's primary nameserver.",
				Optional:            true,
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *PKIExternalCADNSProviderAzureResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExternalCADNSProviderAzureModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Write-only fields are nullified in the plan by the framework; read from config.
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldClientSecretWO), &data.ClientSecretWO)...)
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

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), azureAffix, data.Name.ValueString())

	vaultReq, diags := buildAzureRequest(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createResp, err := cli.Logical().WriteWithContext(ctx, vaultPath, vaultReq)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, createResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderAzureResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExternalCADNSProviderAzureModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), azureAffix, data.Name.ValueString())

	readResp, err := cli.Logical().ReadWithContext(ctx, vaultPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, readResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderAzureResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PKIExternalCADNSProviderAzureModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Write-only fields are nullified in the plan by the framework; read from config.
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldClientSecretWO), &data.ClientSecretWO)...)
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

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), azureAffix, data.Name.ValueString())

	vaultReq, diags := buildAzureRequest(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateResp, err := cli.Logical().WriteWithContext(ctx, vaultPath, vaultReq)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, updateResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderAzureResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PKIExternalCADNSProviderAzureModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), azureAffix, data.Name.ValueString())

	if _, err := cli.Logical().DeleteWithContext(ctx, vaultPath); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *PKIExternalCADNSProviderAzureResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := azureIDRe.FindStringSubmatch(req.ID)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<mount>/%s/<name>', got: %s", azureAffix, req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), matches[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), matches[2])...)
}

func buildAzureRequest(ctx context.Context, data *PKIExternalCADNSProviderAzureModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics
	req := map[string]any{}

	if !data.TTL.IsNull() && !data.TTL.IsUnknown() {
		req[consts.FieldTTL] = data.TTL.ValueInt64()
	}

	var ids []string
	diags.Append(data.Identifiers.ElementsAs(ctx, &ids, false)...)
	if !diags.HasError() {
		req[consts.FieldIdentifiers] = ids
	}

	setIfNotEmpty(req, consts.FieldZoneName, data.ZoneName.ValueString())
	setIfNotEmpty(req, consts.FieldClientID, data.ClientID.ValueString())
	setIfNotEmpty(req, consts.FieldClientSecret, data.ClientSecretWO.ValueString())
	setIfNotEmpty(req, consts.FieldTenantID, data.TenantID.ValueString())
	setIfNotEmpty(req, consts.FieldSubscriptionID, data.SubscriptionID.ValueString())
	setIfNotEmpty(req, consts.FieldResourceGroupName, data.ResourceGroupName.ValueString())
	setIfNotEmpty(req, consts.FieldEnvironment, data.Environment.ValueString())
	setIfNotEmpty(req, consts.FieldNameserver, data.Nameserver.ValueString())

	return req, diags
}

func (r *PKIExternalCADNSProviderAzureResource) populateDataModelFromAPI(ctx context.Context, data *PKIExternalCADNSProviderAzureModel, resp *api.Secret) (rd diag.Diagnostics) {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp PKIExternalCADNSProviderAzureAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}

	data.CreationDate = types.StringValue(readResp.CreationDate)
	data.LastUpdatedDate = types.StringValue(readResp.LastUpdatedDate)

	if readResp.TTL != "" {
		d, err := time.ParseDuration(readResp.TTL)
		if err != nil {
			rd.AddError("Unable to parse TTL from Vault response", fmt.Sprintf("Cannot parse TTL %q as a duration: %s", readResp.TTL, err))
			return
		}
		data.TTL = types.Int64Value(int64(d.Seconds()))
	}

	if readResp.Identifiers != nil {
		ids, diags := types.ListValueFrom(ctx, types.StringType, readResp.Identifiers)
		rd.Append(diags...)
		if !rd.HasError() {
			data.Identifiers = ids
		}
	}

	setStringIfNotEmpty(&data.ZoneName, readResp.ZoneName)
	setStringIfNotEmpty(&data.ClientID, readResp.ClientID)
	setStringIfNotEmpty(&data.TenantID, readResp.TenantID)
	setStringIfNotEmpty(&data.SubscriptionID, readResp.SubscriptionID)
	setStringIfNotEmpty(&data.ResourceGroupName, readResp.ResourceGroupName)
	setStringIfNotEmpty(&data.Environment, readResp.Environment)
	setStringIfNotEmpty(&data.Nameserver, readResp.Nameserver)
	// client_secret_wo intentionally not read back — write-only

	return rd
}
