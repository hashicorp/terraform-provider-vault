// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
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

const dnsProviderAffix = "config/dns-provider"

var dnsProviderIDRe = regexp.MustCompile(`^([^/]+)/` + dnsProviderAffix + `/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &PKIExternalCADNSProviderConfigResource{}

// NewPKIExternalCADNSProviderConfigResource returns the implementation for this resource.
func NewPKIExternalCADNSProviderConfigResource() resource.Resource {
	return &PKIExternalCADNSProviderConfigResource{}
}

// PKIExternalCADNSProviderConfigResource implements the methods that define this resource.
type PKIExternalCADNSProviderConfigResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// PKIExternalCADNSProviderConfigModel is the Terraform resource data model.
type PKIExternalCADNSProviderConfigModel struct {
	base.BaseModel

	Mount      types.String `tfsdk:"mount"`
	Name       types.String `tfsdk:"name"`
	Type       types.String `tfsdk:"type"`
	Identifiers types.List  `tfsdk:"identifiers"`
	TTL        types.String `tfsdk:"ttl"`

	// Computed
	CreationDate    types.String `tfsdk:"creation_date"`
	LastUpdatedDate types.String `tfsdk:"last_updated_date"`

	// AWS Route53 fields
	AccessKeyId   types.String `tfsdk:"access_key_id"`
	Region        types.String `tfsdk:"region"`
	HostedZoneId  types.String `tfsdk:"hosted_zone_id"`
	ExternalId    types.String `tfsdk:"external_id"`
	AssumeRoleArn types.String `tfsdk:"assume_role_arn"`

	// RFC2136 fields
	Nameserver    types.String `tfsdk:"nameserver"`
	TsigKeyName   types.String `tfsdk:"tsig_key_name"`
	TsigSecret    types.String `tfsdk:"tsig_secret"`
	TsigAlgorithm types.String `tfsdk:"tsig_algorithm"`

	// GCP fields
	Credentials               types.String `tfsdk:"credentials"`
	Project                   types.String `tfsdk:"project"`
	ZoneName                  types.String `tfsdk:"zone_name"`
	ImpersonateServiceAccount types.String `tfsdk:"impersonate_service_account"`

	// Azure fields
	ClientId          types.String `tfsdk:"client_id"`
	ClientSecret      types.String `tfsdk:"client_secret"`
	TenantId          types.String `tfsdk:"tenant_id"`
	SubscriptionId    types.String `tfsdk:"subscription_id"`
	ResourceGroupName types.String `tfsdk:"resource_group_name"`
	Environment       types.String `tfsdk:"environment"`
}

// PKIExternalCADNSProviderConfigAPIModel is the Vault API data model.
type PKIExternalCADNSProviderConfigAPIModel struct {
	Name            string   `json:"name" mapstructure:"name"`
	Type            string   `json:"type" mapstructure:"type"`
	Identifiers     []string `json:"identifiers" mapstructure:"identifiers"`
	TTL             string   `json:"ttl" mapstructure:"ttl"`
	CreationDate    string   `json:"creation_date" mapstructure:"creation_date"`
	LastUpdatedDate string   `json:"last_updated_date" mapstructure:"last_updated_date"`

	// AWS Route53
	AccessKeyId   string `json:"access_key_id" mapstructure:"access_key_id"`
	Region        string `json:"region" mapstructure:"region"`
	HostedZoneId  string `json:"hosted_zone_id" mapstructure:"hosted_zone_id"`
	ExternalId    string `json:"external_id" mapstructure:"external_id"`
	AssumeRoleArn string `json:"assume_role_arn" mapstructure:"assume_role_arn"`

	// RFC2136
	Nameserver    string `json:"nameserver" mapstructure:"nameserver"`
	TsigKeyName   string `json:"tsig_key_name" mapstructure:"tsig_key_name"`
	TsigAlgorithm string `json:"tsig_algorithm" mapstructure:"tsig_algorithm"`

	// GCP
	Project                   string `json:"project" mapstructure:"project"`
	ZoneName                  string `json:"zone_name" mapstructure:"zone_name"`
	ImpersonateServiceAccount string `json:"impersonate_service_account" mapstructure:"impersonate_service_account"`

	// Azure
	ClientId          string `json:"client_id" mapstructure:"client_id"`
	TenantId          string `json:"tenant_id" mapstructure:"tenant_id"`
	SubscriptionId    string `json:"subscription_id" mapstructure:"subscription_id"`
	ResourceGroupName string `json:"resource_group_name" mapstructure:"resource_group_name"`
	Environment       string `json:"environment" mapstructure:"environment"`
}

func (r *PKIExternalCADNSProviderConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_external_ca_secret_backend_dns_provider"
}

func (r *PKIExternalCADNSProviderConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a DNS provider configuration for PKI External CA DNS-01 ACME challenges.",
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
			"type": schema.StringAttribute{
				MarkdownDescription: "The DNS provider type. Valid values: `aws_route53`, `rfc2136`, `gcp`, `azure`.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.OneOf("aws_route53", "rfc2136", "gcp", "azure"),
				},
			},
			"identifiers": schema.ListAttribute{
				MarkdownDescription: "List of domain identifiers this provider handles.",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers:       []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"ttl": schema.StringAttribute{
				MarkdownDescription: "TTL for DNS records created by this provider (e.g. `60s`, `5m`).",
				Optional:            true,
				Computed:            true,
			},
			"creation_date": schema.StringAttribute{
				MarkdownDescription: "The date and time the provider was created in RFC3339 format.",
				Computed:            true,
			},
			"last_updated_date": schema.StringAttribute{
				MarkdownDescription: "The date and time the provider was last updated in RFC3339 format.",
				Computed:            true,
			},

			// AWS Route53
			"access_key_id": schema.StringAttribute{
				MarkdownDescription: "(AWS Route53) The AWS access key ID.",
				Optional:            true,
			},
			"region": schema.StringAttribute{
				MarkdownDescription: "(AWS Route53) The AWS region.",
				Optional:            true,
			},
			"hosted_zone_id": schema.StringAttribute{
				MarkdownDescription: "(AWS Route53) The Route53 hosted zone ID.",
				Optional:            true,
			},
			"external_id": schema.StringAttribute{
				MarkdownDescription: "(AWS Route53) External ID for assume role.",
				Optional:            true,
			},
			"assume_role_arn": schema.StringAttribute{
				MarkdownDescription: "(AWS Route53) ARN of the IAM role to assume.",
				Optional:            true,
			},

			// RFC2136
			"nameserver": schema.StringAttribute{
				MarkdownDescription: "(RFC2136) The nameserver address (host:port).",
				Optional:            true,
			},
			"tsig_key_name": schema.StringAttribute{
				MarkdownDescription: "(RFC2136) TSIG key name.",
				Optional:            true,
			},
			"tsig_secret": schema.StringAttribute{
				MarkdownDescription: "(RFC2136) TSIG secret. Write-only — not returned by Vault.",
				Optional:            true,
				Sensitive:           true,
			},
			"tsig_algorithm": schema.StringAttribute{
				MarkdownDescription: "(RFC2136) TSIG algorithm.",
				Optional:            true,
			},

			// GCP
			"credentials": schema.StringAttribute{
				MarkdownDescription: "(GCP) Service account JSON credentials. Write-only — not returned by Vault.",
				Optional:            true,
				Sensitive:           true,
			},
			"project": schema.StringAttribute{
				MarkdownDescription: "(GCP) GCP project ID.",
				Optional:            true,
			},
			"zone_name": schema.StringAttribute{
				MarkdownDescription: "(GCP / Azure) DNS zone name.",
				Optional:            true,
			},
			"impersonate_service_account": schema.StringAttribute{
				MarkdownDescription: "(GCP) Service account to impersonate.",
				Optional:            true,
			},

			// Azure
			"client_id": schema.StringAttribute{
				MarkdownDescription: "(Azure) Azure client (application) ID.",
				Optional:            true,
			},
			"client_secret": schema.StringAttribute{
				MarkdownDescription: "(Azure) Azure client secret. Write-only — not returned by Vault.",
				Optional:            true,
				Sensitive:           true,
			},
			"tenant_id": schema.StringAttribute{
				MarkdownDescription: "(Azure) Azure tenant ID.",
				Optional:            true,
			},
			"subscription_id": schema.StringAttribute{
				MarkdownDescription: "(Azure) Azure subscription ID.",
				Optional:            true,
			},
			"resource_group_name": schema.StringAttribute{
				MarkdownDescription: "(Azure) Azure resource group name containing the DNS zone.",
				Optional:            true,
			},
			"environment": schema.StringAttribute{
				MarkdownDescription: "(Azure) Azure environment. Valid values: `AzurePublic`, `AzureChina`, `AzureGovernment`.",
				Optional:            true,
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *PKIExternalCADNSProviderConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExternalCADNSProviderConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := checkVaultVersion(r.Meta()); err != nil {
		resp.Diagnostics.AddError("Vault Version Check Failed", err.Error())
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	path := fmt.Sprintf("%s/%s/%s", mount, dnsProviderAffix, name)

	vaultRequest, diags := buildDNSProviderVaultRequest(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createResp, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	resp.Diagnostics.Append(handleDNSProviderResponse(ctx, &data, createResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExternalCADNSProviderConfigModel
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
	path := fmt.Sprintf("%s/%s/%s", mount, dnsProviderAffix, name)

	readResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(handleDNSProviderResponse(ctx, &data, readResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PKIExternalCADNSProviderConfigModel
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
	path := fmt.Sprintf("%s/%s/%s", mount, dnsProviderAffix, name)

	vaultRequest, diags := buildDNSProviderVaultRequest(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateResp, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	resp.Diagnostics.Append(handleDNSProviderResponse(ctx, &data, updateResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PKIExternalCADNSProviderConfigModel
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
	path := fmt.Sprintf("%s/%s/%s", mount, dnsProviderAffix, name)

	if _, err := cli.Logical().DeleteWithContext(ctx, path); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *PKIExternalCADNSProviderConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := dnsProviderIDRe.FindStringSubmatch(req.ID)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<mount>/%s/<name>', got: %s", dnsProviderAffix, req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), matches[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), matches[2])...)
}

// buildDNSProviderVaultRequest constructs the map to send to Vault from the Terraform model.
func buildDNSProviderVaultRequest(ctx context.Context, data *PKIExternalCADNSProviderConfigModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	req := map[string]any{
		"type": data.Type.ValueString(),
	}

	if !data.TTL.IsNull() && !data.TTL.IsUnknown() {
		req["ttl"] = data.TTL.ValueString()
	}

	if !data.Identifiers.IsNull() && !data.Identifiers.IsUnknown() {
		var ids []string
		diags.Append(data.Identifiers.ElementsAs(ctx, &ids, false)...)
		if diags.HasError() {
			return nil, diags
		}
		req["identifiers"] = ids
	}

	switch data.Type.ValueString() {
	case "aws_route53":
		setIfNotEmpty(req, "access_key_id", data.AccessKeyId.ValueString())
		setIfNotEmpty(req, "region", data.Region.ValueString())
		setIfNotEmpty(req, "hosted_zone_id", data.HostedZoneId.ValueString())
		setIfNotEmpty(req, "external_id", data.ExternalId.ValueString())
		setIfNotEmpty(req, "assume_role_arn", data.AssumeRoleArn.ValueString())
	case "rfc2136":
		setIfNotEmpty(req, "nameserver", data.Nameserver.ValueString())
		setIfNotEmpty(req, "tsig_key_name", data.TsigKeyName.ValueString())
		setIfNotEmpty(req, "tsig_secret", data.TsigSecret.ValueString())
		setIfNotEmpty(req, "tsig_algorithm", data.TsigAlgorithm.ValueString())
	case "gcp":
		setIfNotEmpty(req, "credentials", data.Credentials.ValueString())
		setIfNotEmpty(req, "project", data.Project.ValueString())
		setIfNotEmpty(req, "zone_name", data.ZoneName.ValueString())
		setIfNotEmpty(req, "impersonate_service_account", data.ImpersonateServiceAccount.ValueString())
	case "azure":
		setIfNotEmpty(req, "zone_name", data.ZoneName.ValueString())
		setIfNotEmpty(req, "client_id", data.ClientId.ValueString())
		setIfNotEmpty(req, "client_secret", data.ClientSecret.ValueString())
		setIfNotEmpty(req, "tenant_id", data.TenantId.ValueString())
		setIfNotEmpty(req, "subscription_id", data.SubscriptionId.ValueString())
		setIfNotEmpty(req, "resource_group_name", data.ResourceGroupName.ValueString())
		setIfNotEmpty(req, "environment", data.Environment.ValueString())
	}

	return req, diags
}

// handleDNSProviderResponse maps the Vault API response back into the Terraform model.
// Write-only fields (tsig_secret, credentials, client_secret) are intentionally skipped
// as Vault does not return them.
func handleDNSProviderResponse(ctx context.Context, data *PKIExternalCADNSProviderConfigModel, readResp *api.Secret) (rd diag.Diagnostics) {
	var apiModel PKIExternalCADNSProviderConfigAPIModel
	if err := model.ToAPIModel(readResp.Data, &apiModel); err != nil {
		rd.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.Type = types.StringValue(apiModel.Type)
	data.CreationDate = types.StringValue(apiModel.CreationDate)
	data.LastUpdatedDate = types.StringValue(apiModel.LastUpdatedDate)

	if apiModel.TTL != "" {
		data.TTL = types.StringValue(apiModel.TTL)
	}

	// Identifiers — only set when Vault returns a non-nil list.
	if apiModel.Identifiers != nil {
		ids, diags := types.ListValueFrom(ctx, types.StringType, apiModel.Identifiers)
		rd.Append(diags...)
		if !rd.HasError() {
			data.Identifiers = ids
		}
	}

	// Provider-specific fields: only set fields that the API returned a value for,
	// so that fields belonging to other provider types don't overwrite config with "".
	setStringIfNotEmpty := func(target *types.String, val string) {
		if val != "" {
			*target = types.StringValue(val)
		}
	}

	// AWS Route53
	setStringIfNotEmpty(&data.AccessKeyId, apiModel.AccessKeyId)
	setStringIfNotEmpty(&data.Region, apiModel.Region)
	setStringIfNotEmpty(&data.HostedZoneId, apiModel.HostedZoneId)
	setStringIfNotEmpty(&data.ExternalId, apiModel.ExternalId)
	setStringIfNotEmpty(&data.AssumeRoleArn, apiModel.AssumeRoleArn)

	// RFC2136
	setStringIfNotEmpty(&data.Nameserver, apiModel.Nameserver)
	setStringIfNotEmpty(&data.TsigKeyName, apiModel.TsigKeyName)
	setStringIfNotEmpty(&data.TsigAlgorithm, apiModel.TsigAlgorithm)
	// tsig_secret intentionally not read back — write-only

	// GCP
	setStringIfNotEmpty(&data.Project, apiModel.Project)
	setStringIfNotEmpty(&data.ZoneName, apiModel.ZoneName)
	setStringIfNotEmpty(&data.ImpersonateServiceAccount, apiModel.ImpersonateServiceAccount)
	// credentials intentionally not read back — write-only

	// Azure
	setStringIfNotEmpty(&data.ClientId, apiModel.ClientId)
	setStringIfNotEmpty(&data.TenantId, apiModel.TenantId)
	setStringIfNotEmpty(&data.SubscriptionId, apiModel.SubscriptionId)
	setStringIfNotEmpty(&data.ResourceGroupName, apiModel.ResourceGroupName)
	setStringIfNotEmpty(&data.Environment, apiModel.Environment)
	// client_secret intentionally not read back — write-only

	return rd
}

// setIfNotEmpty adds key=value to the map only when value is non-empty.
func setIfNotEmpty(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}
