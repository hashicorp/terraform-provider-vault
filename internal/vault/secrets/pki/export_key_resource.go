// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki

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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/vault/api"
)

var exportKeyIDRegexp = regexp.MustCompile(`^(.+)/export/([^/]+)$`)

var _ resource.ResourceWithImportState = &PKIExportKeyResource{}

func NewPKIExportKeyResource() resource.Resource {
	return &PKIExportKeyResource{}
}

// PKIExportKeyResource manages a wrapping keypair on a PKI mount for BYOK CA migration.
type PKIExportKeyResource struct {
	base.ResourceWithConfigure
}

type PKIExportKeyModel struct {
	base.BaseModel

	Mount         types.String `tfsdk:"mount"`
	KeyType       types.String `tfsdk:"key_type"`
	Name          types.String `tfsdk:"name"`
	ExportKeyUUID types.String `tfsdk:"export_key_uuid"`
	PublicKey     types.String `tfsdk:"public_key"`
	ExportKeyHMAC types.String `tfsdk:"export_key_hmac"`
	CreatedAt     types.String `tfsdk:"created_at"`
}

type PKIExportKeyAPIModel struct {
	ExportKeyUUID string `json:"export_key_uuid" mapstructure:"export_key_uuid"`
	Name          string `json:"name"            mapstructure:"name"`
	KeyType       string `json:"key_type"        mapstructure:"key_type"`
	PublicKey     string `json:"public_key"      mapstructure:"public_key"`
	ExportKeyHMAC string `json:"export_key_hmac" mapstructure:"export_key_hmac"`
	CreatedAt     string `json:"created_at"      mapstructure:"created_at"`
}

type PKIExportKeyWriteAPIModel struct {
	KeyType string `mapstructure:"key_type"`
	Name    string `mapstructure:"name,omitempty"`
}

func (r *PKIExportKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_secret_backend_export_key"
}

func (r *PKIExportKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a wrapping keypair on a PKI secrets engine mount for BYOK CA migration.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Description: "Path of the PKI secrets engine mount.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_type": schema.StringAttribute{
				Description: "Algorithm for the wrapping keypair.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Human-readable name for this export key.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"export_key_uuid": schema.StringAttribute{
				Description: "UUID assigned by Vault to this export key.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"public_key": schema.StringAttribute{
				Description: "PEM-encoded public key returned by Vault.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"export_key_hmac": schema.StringAttribute{
				Description: "Deterministic fingerprint of the public key.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Description: "RFC3339 timestamp of when this export key was created.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

// Create calls POST /:mount/export to generate the keypair, then calls Read to populate created_at.
func (r *PKIExportKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExportKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	requestBody, diags := r.buildWriteRequest(&data)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	vaultResp, err := vaultClient.Logical().WriteWithContext(ctx, r.exportPath(data.Mount.ValueString()), requestBody)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}
	if vaultResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	uuid, ok := vaultResp.Data["export_key_uuid"].(string)
	if !ok || uuid == "" {
		resp.Diagnostics.AddError("Unexpected Vault response", "export_key_uuid missing from create response")
		return
	}
	data.ExportKeyUUID = types.StringValue(uuid)

	if diags := r.readIntoModel(ctx, vaultClient, &data); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read calls GET /:mount/export/:uuid to refresh all attributes.
func (r *PKIExportKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExportKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	diags := r.readIntoModel(ctx, vaultClient, &data)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is a no-op as all configurable attributes require replacement.
func (r *PKIExportKeyResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

// Delete calls DELETE /:mount/export/:uuid to remove the wrapping keypair from Vault.
func (r *PKIExportKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PKIExportKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	_, err = vaultClient.Logical().DeleteWithContext(ctx, r.exportKeyPath(data.Mount.ValueString(), data.ExportKeyUUID.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
	}
}

// ImportState imports an existing export key using the ID format <mount>/export/<uuid>.
func (r *PKIExportKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount, uuid, err := parseExportKeyID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import identifier",
			fmt.Sprintf("Expected <mount>/export/<uuid>, got %q: %s", req.ID, err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("export_key_uuid"), uuid)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(ctx, fmt.Sprintf("Environment variable %s set, importing namespace into state", consts.EnvVarVaultNamespaceImport))
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

func (r *PKIExportKeyResource) readIntoModel(ctx context.Context, vaultClient *api.Client, data *PKIExportKeyModel) diag.Diagnostics {
	vaultResp, err := vaultClient.Logical().ReadWithContext(ctx, r.exportKeyPath(data.Mount.ValueString(), data.ExportKeyUUID.ValueString()))
	if err != nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic(errutil.VaultReadErr(err))}
	}
	if vaultResp == nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic(errutil.VaultReadResponseNil())}
	}

	var apiModel PKIExportKeyAPIModel
	if err := model.ToAPIModel(vaultResp.Data, &apiModel); err != nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Unable to decode Vault response", err.Error())}
	}

	data.ExportKeyUUID = types.StringValue(apiModel.ExportKeyUUID)
	data.KeyType = types.StringValue(apiModel.KeyType)
	data.PublicKey = types.StringValue(apiModel.PublicKey)
	data.ExportKeyHMAC = types.StringValue(apiModel.ExportKeyHMAC)
	data.CreatedAt = types.StringValue(apiModel.CreatedAt)

	if apiModel.Name != "" {
		data.Name = types.StringValue(apiModel.Name)
	} else {
		data.Name = types.StringNull()
	}

	return nil
}

func (r *PKIExportKeyResource) buildWriteRequest(data *PKIExportKeyModel) (map[string]any, diag.Diagnostics) {
	apiModel := PKIExportKeyWriteAPIModel{
		KeyType: data.KeyType.ValueString(),
		Name:    data.Name.ValueString(),
	}

	var out map[string]any
	if err := mapstructure.Decode(apiModel, &out); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to encode export key request", err.Error()),
		}
	}

	return out, nil
}

func (r *PKIExportKeyResource) exportPath(mount string) string {
	return fmt.Sprintf("%s/export", mount)
}

func (r *PKIExportKeyResource) exportKeyPath(mount, uuid string) string {
	return fmt.Sprintf("%s/export/%s", mount, uuid)
}

func parseExportKeyID(id string) (mount, uuid string, err error) {
	id = strings.Trim(id, "/")
	matches := exportKeyIDRegexp.FindStringSubmatch(id)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("must be of the form <mount>/export/<uuid>")
	}
	return matches[1], matches[2], nil
}
