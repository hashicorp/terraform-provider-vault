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

const gcpAffix = "config/dns/google-cloud-dns"

var gcpIDRe = regexp.MustCompile(`^(.+)/` + gcpAffix + `/([^/]+)$`)

var _ resource.ResourceWithConfigure = &PKIExternalCADNSProviderGCPResource{}

func NewPKIExternalCADNSProviderGCPResource() resource.Resource {
	return &PKIExternalCADNSProviderGCPResource{}
}

type PKIExternalCADNSProviderGCPResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type PKIExternalCADNSProviderGCPModel struct {
	base.BaseModel

	Mount       types.String `tfsdk:"mount"`
	Name        types.String `tfsdk:"name"`
	Identifiers types.List   `tfsdk:"identifiers"`
	TTL         types.Int64  `tfsdk:"ttl"`

	// Computed
	CreationDate    types.String `tfsdk:"creation_date"`
	LastUpdatedDate types.String `tfsdk:"last_updated_date"`

	// Provider-specific
	CredentialsWO             types.String `tfsdk:"credentials_wo"`
	CredentialsWOVersion      types.Int64  `tfsdk:"credentials_wo_version"`
	Project                   types.String `tfsdk:"project"`
	ZoneName                  types.String `tfsdk:"zone_name"`
	ImpersonateServiceAccount types.String `tfsdk:"impersonate_service_account"`
	Nameserver                types.String `tfsdk:"nameserver"`
}

type PKIExternalCADNSProviderGCPAPIModel struct {
	Name                      string   `json:"name" mapstructure:"name"`
	Identifiers               []string `json:"identifiers" mapstructure:"identifiers"`
	TTL                       string   `json:"ttl" mapstructure:"ttl"`
	CreationDate              string   `json:"creation_date" mapstructure:"creation_date"`
	LastUpdatedDate           string   `json:"last_updated_date" mapstructure:"last_updated_date"`
	Project                   string   `json:"project" mapstructure:"project"`
	ZoneName                  string   `json:"zone_name" mapstructure:"zone_name"`
	ImpersonateServiceAccount string   `json:"impersonate_service_account" mapstructure:"impersonate_service_account"`
	Nameserver                string   `json:"nameserver" mapstructure:"nameserver"`
}

func (r *PKIExternalCADNSProviderGCPResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_external_ca_secret_backend_dns_provider_gcp"
}

func (r *PKIExternalCADNSProviderGCPResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Google Cloud DNS provider configuration for PKI External CA DNS-01 ACME challenges.",
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
			consts.FieldCredentialsWO: schema.StringAttribute{
				MarkdownDescription: "GCP service account credentials as JSON content. Write-only — not returned by Vault.",
				Optional:            true,
				WriteOnly:           true,
			},
			consts.FieldCredentialsWOVersion: schema.Int64Attribute{
				MarkdownDescription: "Version counter for the write-only `credentials` field. Increment this value to trigger an update to the credentials in Vault.",
				Optional:            true,
			},
			consts.FieldProject: schema.StringAttribute{
				MarkdownDescription: "GCP project name.",
				Optional:            true,
			},
			consts.FieldZoneName: schema.StringAttribute{
				MarkdownDescription: "GCP Cloud DNS zone name.",
				Optional:            true,
			},
			consts.FieldImpersonateServiceAccount: schema.StringAttribute{
				MarkdownDescription: "Service account email to impersonate.",
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

func (r *PKIExternalCADNSProviderGCPResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExternalCADNSProviderGCPModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Write-only fields are nullified in the plan by the framework; read from config.
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldCredentialsWO), &data.CredentialsWO)...)
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

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), gcpAffix, data.Name.ValueString())

	vaultReq, diags := buildGCPRequest(ctx, &data)
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

func (r *PKIExternalCADNSProviderGCPResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExternalCADNSProviderGCPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), gcpAffix, data.Name.ValueString())

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

func (r *PKIExternalCADNSProviderGCPResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PKIExternalCADNSProviderGCPModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Write-only fields are nullified in the plan by the framework; read from config.
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldCredentialsWO), &data.CredentialsWO)...)
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

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), gcpAffix, data.Name.ValueString())

	vaultReq, diags := buildGCPRequest(ctx, &data)
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

func (r *PKIExternalCADNSProviderGCPResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PKIExternalCADNSProviderGCPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), gcpAffix, data.Name.ValueString())

	if _, err := cli.Logical().DeleteWithContext(ctx, vaultPath); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *PKIExternalCADNSProviderGCPResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := gcpIDRe.FindStringSubmatch(req.ID)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<mount>/%s/<name>', got: %s", gcpAffix, req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), matches[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), matches[2])...)
}

func buildGCPRequest(ctx context.Context, data *PKIExternalCADNSProviderGCPModel) (map[string]any, diag.Diagnostics) {
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

	setIfNotEmpty(req, consts.FieldCredentials, data.CredentialsWO.ValueString())
	setIfNotEmpty(req, consts.FieldProject, data.Project.ValueString())
	setIfNotEmpty(req, consts.FieldZoneName, data.ZoneName.ValueString())
	setIfNotEmpty(req, consts.FieldImpersonateServiceAccount, data.ImpersonateServiceAccount.ValueString())
	setIfNotEmpty(req, consts.FieldNameserver, data.Nameserver.ValueString())

	return req, diags
}

func (r *PKIExternalCADNSProviderGCPResource) populateDataModelFromAPI(ctx context.Context, data *PKIExternalCADNSProviderGCPModel, resp *api.Secret) (rd diag.Diagnostics) {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp PKIExternalCADNSProviderGCPAPIModel
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

	setStringIfNotEmpty(&data.Project, readResp.Project)
	setStringIfNotEmpty(&data.ZoneName, readResp.ZoneName)
	setStringIfNotEmpty(&data.ImpersonateServiceAccount, readResp.ImpersonateServiceAccount)
	setStringIfNotEmpty(&data.Nameserver, readResp.Nameserver)
	// credentials_wo intentionally not read back — write-only

	return rd
}
