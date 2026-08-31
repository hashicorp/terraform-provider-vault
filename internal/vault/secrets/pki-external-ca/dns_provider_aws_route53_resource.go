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

const awsRoute53Affix = "config/dns/aws-route53"

var awsRoute53IDRe = regexp.MustCompile(`^([^/]+)/` + awsRoute53Affix + `/([^/]+)$`)

var _ resource.ResourceWithConfigure = &PKIExternalCADNSProviderAWSRoute53Resource{}

func NewPKIExternalCADNSProviderAWSRoute53Resource() resource.Resource {
	return &PKIExternalCADNSProviderAWSRoute53Resource{}
}

type PKIExternalCADNSProviderAWSRoute53Resource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type PKIExternalCADNSProviderAWSRoute53Model struct {
	base.BaseModel

	Mount       types.String `tfsdk:"mount"`
	Name        types.String `tfsdk:"name"`
	Identifiers types.List   `tfsdk:"identifiers"`
	TTL         types.String `tfsdk:"ttl"`

	// Computed
	CreationDate    types.String `tfsdk:"creation_date"`
	LastUpdatedDate types.String `tfsdk:"last_updated_date"`

	// Provider-specific
	AccessKeyId     types.String `tfsdk:"access_key_id"`
	SecretAccessKey types.String `tfsdk:"secret_access_key"`
	Region          types.String `tfsdk:"region"`
	HostedZoneId    types.String `tfsdk:"hosted_zone_id"`
	ExternalID      types.String `tfsdk:"external_id"`
	AssumeRoleArn   types.String `tfsdk:"assume_role_arn"`
	Nameserver      types.String `tfsdk:"nameserver"`
}

type PKIExternalCADNSProviderAWSRoute53APIModel struct {
	Name            string   `json:"name" mapstructure:"name"`
	Identifiers     []string `json:"identifiers" mapstructure:"identifiers"`
	TTL             string   `json:"ttl" mapstructure:"ttl"`
	CreationDate    string   `json:"creation_date" mapstructure:"creation_date"`
	LastUpdatedDate string   `json:"last_updated_date" mapstructure:"last_updated_date"`
	AccessKeyId     string   `json:"access_key_id" mapstructure:"access_key_id"`
	Region          string   `json:"region" mapstructure:"region"`
	HostedZoneId    string   `json:"hosted_zone_id" mapstructure:"hosted_zone_id"`
	ExternalID      string   `json:"external_id" mapstructure:"external_id"`
	AssumeRoleArn   string   `json:"assume_role_arn" mapstructure:"assume_role_arn"`
	Nameserver      string   `json:"nameserver" mapstructure:"nameserver"`
}

func (r *PKIExternalCADNSProviderAWSRoute53Resource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_external_ca_secret_backend_dns_provider_aws_route53"
}

func (r *PKIExternalCADNSProviderAWSRoute53Resource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an AWS Route53 DNS provider configuration for PKI External CA DNS-01 ACME challenges.",
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
			consts.FieldAccessKeyID: schema.StringAttribute{
				MarkdownDescription: "AWS access key ID for Route53 API access.",
				Optional:            true,
			},
			consts.FieldSecretAccessKey: schema.StringAttribute{
				MarkdownDescription: "AWS secret access key for Route53 API access. Write-only — not returned by Vault.",
				Optional:            true,
				WriteOnly:           true,
			},
			consts.FieldRegion: schema.StringAttribute{
				MarkdownDescription: "AWS region for Route53 operations. Defaults to `us-east-1`.",
				Optional:            true,
			},
			consts.FieldHostedZoneID: schema.StringAttribute{
				MarkdownDescription: "AWS Route53 hosted zone ID.",
				Optional:            true,
			},
			consts.FieldExternalID: schema.StringAttribute{
				MarkdownDescription: "External ID for AWS STS AssumeRole.",
				Optional:            true,
			},
			consts.FieldAssumeRoleArn: schema.StringAttribute{
				MarkdownDescription: "AWS IAM role ARN to assume for Route53 operations.",
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

func (r *PKIExternalCADNSProviderAWSRoute53Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExternalCADNSProviderAWSRoute53Model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Write-only fields are nullified in the plan by the framework; read from config.
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldSecretAccessKey), &data.SecretAccessKey)...)
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

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), awsRoute53Affix, data.Name.ValueString())

	vaultReq, diags := buildAWSRoute53Request(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createResp, err := cli.Logical().WriteWithContext(ctx, vaultPath, vaultReq)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	resp.Diagnostics.Append(handleAWSRoute53Response(ctx, &data, createResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderAWSRoute53Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExternalCADNSProviderAWSRoute53Model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), awsRoute53Affix, data.Name.ValueString())

	readResp, err := cli.Logical().ReadWithContext(ctx, vaultPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(handleAWSRoute53Response(ctx, &data, readResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderAWSRoute53Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PKIExternalCADNSProviderAWSRoute53Model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Write-only fields are nullified in the plan by the framework; read from config.
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldSecretAccessKey), &data.SecretAccessKey)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), awsRoute53Affix, data.Name.ValueString())

	vaultReq, diags := buildAWSRoute53Request(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateResp, err := cli.Logical().WriteWithContext(ctx, vaultPath, vaultReq)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	resp.Diagnostics.Append(handleAWSRoute53Response(ctx, &data, updateResp)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCADNSProviderAWSRoute53Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PKIExternalCADNSProviderAWSRoute53Model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := fmt.Sprintf("%s/%s/%s", data.Mount.ValueString(), awsRoute53Affix, data.Name.ValueString())

	if _, err := cli.Logical().DeleteWithContext(ctx, vaultPath); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *PKIExternalCADNSProviderAWSRoute53Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := awsRoute53IDRe.FindStringSubmatch(req.ID)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<mount>/%s/<name>', got: %s", awsRoute53Affix, req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), matches[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), matches[2])...)
}

func buildAWSRoute53Request(ctx context.Context, data *PKIExternalCADNSProviderAWSRoute53Model) (map[string]any, diag.Diagnostics) {
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

	setIfNotEmpty(req, consts.FieldAccessKeyID, data.AccessKeyId.ValueString())
	setIfNotEmpty(req, consts.FieldSecretAccessKey, data.SecretAccessKey.ValueString())
	setIfNotEmpty(req, consts.FieldRegion, data.Region.ValueString())
	setIfNotEmpty(req, consts.FieldHostedZoneID, data.HostedZoneId.ValueString())
	setIfNotEmpty(req, consts.FieldExternalID, data.ExternalID.ValueString())
	setIfNotEmpty(req, consts.FieldAssumeRoleArn, data.AssumeRoleArn.ValueString())
	setIfNotEmpty(req, consts.FieldNameserver, data.Nameserver.ValueString())

	return req, diags
}

func handleAWSRoute53Response(ctx context.Context, data *PKIExternalCADNSProviderAWSRoute53Model, readResp *api.Secret) (rd diag.Diagnostics) {
	var apiModel PKIExternalCADNSProviderAWSRoute53APIModel
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

	setStringIfNotEmpty(&data.AccessKeyId, apiModel.AccessKeyId)
	setStringIfNotEmpty(&data.Region, apiModel.Region)
	setStringIfNotEmpty(&data.HostedZoneId, apiModel.HostedZoneId)
	setStringIfNotEmpty(&data.ExternalID, apiModel.ExternalID)
	setStringIfNotEmpty(&data.AssumeRoleArn, apiModel.AssumeRoleArn)
	setStringIfNotEmpty(&data.Nameserver, apiModel.Nameserver)
	// secret_access_key intentionally not read back — write-only

	return rd
}
