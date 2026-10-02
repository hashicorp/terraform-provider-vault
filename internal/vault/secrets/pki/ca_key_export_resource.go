// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	ephemeralschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/vault/api"
)

var _ ephemeral.EphemeralResource = &PKICAKeyExportEphemeralResource{}

// NewPKICAKeyExportEphemeralResource is the constructor registered in provider.go.
func NewPKICAKeyExportEphemeralResource() ephemeral.EphemeralResource {
	return &PKICAKeyExportEphemeralResource{}
}

// PKICAKeyExportEphemeralResource wraps a CA private key for BYOK migration.
// It is ephemeral because wrapped_key must never be written to Terraform state —
// doing so would expose the CA private key to anyone with state file access.
type PKICAKeyExportEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// PKICAKeyExportModel is the Terraform data model for this ephemeral resource.
// BaseModelEphemeral provides namespace and mount_id. mount_id defers the Open
// call until the PKI mount is known, preventing Terraform from calling Open
// before the mount resource has been created.
type PKICAKeyExportModel struct {
	base.BaseModelEphemeral

	Mount         types.String `tfsdk:"mount"`
	CAKeyUUID     types.String `tfsdk:"ca_key_uuid"`
	PublicKey     types.String `tfsdk:"public_key"`
	WrappedKey    types.String `tfsdk:"wrapped_key"`
	ExportKeyHMAC types.String `tfsdk:"export_key_hmac"`
	ExportedAt    types.String `tfsdk:"exported_at"`
}

// PKICAKeyExportAPIResponse mirrors the four fields Vault returns from
// POST /:mount/keys/:ca_key_uuid/export.
type PKICAKeyExportAPIResponse struct {
	CAKeyUUID     string `json:"ca_key_uuid" mapstructure:"ca_key_uuid"`
	WrappedKey    string `json:"wrapped_key" mapstructure:"wrapped_key"`
	ExportKeyHMAC string `json:"export_key_hmac" mapstructure:"export_key_hmac"`
	ExportedAt    string `json:"exported_at" mapstructure:"exported_at"`
}

func (r *PKICAKeyExportEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_secret_backend_ca_key_export"
}

func (r *PKICAKeyExportEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = ephemeralschema.Schema{
		MarkdownDescription: "Ephemeral resource that wraps a CA private key for BYOK migration. " +
			"The wrapped_key blob is never written to Terraform state.",
		Attributes: map[string]ephemeralschema.Attribute{
			consts.FieldMount: ephemeralschema.StringAttribute{
				Description: "Path of the source PKI secrets engine mount.",
				Required:    true,
			},
			"ca_key_uuid": ephemeralschema.StringAttribute{
				Description: "UUID of the CA key to export from the source mount.",
				Required:    true,
			},
			"public_key": ephemeralschema.StringAttribute{
				Description: "PKIX PEM public key of the destination wrapping key. Obtain from vault_pki_secret_backend_export_key.public_key.",
				Required:    true,
			},
			"wrapped_key": ephemeralschema.StringAttribute{
				Description: "Base64-encoded encrypted blob containing the wrapped CA private key. Pass to vault_pki_secret_backend_wrapped_key_import.",
				Computed:    true,
				Sensitive:   true,
			},
			"export_key_hmac": ephemeralschema.StringAttribute{
				Description: `HMAC fingerprint of the wrapping public key (format "sha256:<hex>"). Pass alongside wrapped_key to the import resource.`,
				Computed:    true,
			},
			"exported_at": ephemeralschema.StringAttribute{
				Description: "RFC3339 timestamp of when the export occurred.",
				Computed:    true,
			},
		},
	}

	// Injects namespace and mount_id required by all ephemeral resources in this provider.
	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Open calls POST /:mount/keys/:ca_key_uuid/export. The ca_key_uuid goes in the
// URL path; only public_key is sent in the request body. Vault wraps the CA private
// key and returns the encrypted blob. The result is written to the ephemeral result,
// never to persistent Terraform state.
func (r *PKICAKeyExportEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data PKICAKeyExportModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultResp, err := vaultClient.Logical().WriteWithContext(
		ctx,
		r.path(data.Mount.ValueString(), data.CAKeyUUID.ValueString()),
		map[string]any{"public_key": data.PublicKey.ValueString()},
	)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}
	if vaultResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diags := r.populateModel(&data, vaultResp); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *PKICAKeyExportEphemeralResource) populateModel(data *PKICAKeyExportModel, vaultResp *api.Secret) diag.Diagnostics {
	if vaultResp == nil || vaultResp.Data == nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil.")}
	}

	var apiResp PKICAKeyExportAPIResponse
	if err := model.ToAPIModel(vaultResp.Data, &apiResp); err != nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Unable to decode Vault response", err.Error())}
	}

	data.WrappedKey = types.StringValue(apiResp.WrappedKey)
	data.ExportKeyHMAC = types.StringValue(apiResp.ExportKeyHMAC)
	data.ExportedAt = types.StringValue(apiResp.ExportedAt)

	return nil
}

// path builds the Vault API path: /:mount/keys/:ca_key_uuid/export
func (r *PKICAKeyExportEphemeralResource) path(mount, caKeyUUID string) string {
	return fmt.Sprintf("%s/keys/%s/export", mount, caKeyUUID)
}
