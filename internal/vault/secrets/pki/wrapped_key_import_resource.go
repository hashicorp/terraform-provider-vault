// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/vault/api"
)

// NewPKIWrappedKeyImportResource is the constructor registered in provider.go.
func NewPKIWrappedKeyImportResource() resource.Resource {
	return &PKIWrappedKeyImportResource{}
}

// PKIWrappedKeyImportResource imports a BYOK-wrapped CA private key into a PKI
// mount. This is a write-only trigger resource: Create fires POST /keys/import
// and records the resulting key_id in Terraform state. There is no BYOK-specific
// Read or Delete endpoint — once imported the key is a standard PKI key whose
// lifecycle is managed outside Terraform. Destroy removes it from Terraform state
// only; the key is not deleted from Vault.
type PKIWrappedKeyImportResource struct {
	base.ResourceWithConfigure
}

// PKIWrappedKeyImportModel is the Terraform state model.
type PKIWrappedKeyImportModel struct {
	base.BaseModel

	Mount         types.String `tfsdk:"mount"`
	KeyName       types.String `tfsdk:"key_name"`
	WrappedKey    types.String `tfsdk:"wrapped_key"`
	ExportKeyHMAC types.String `tfsdk:"export_key_hmac"`
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
}

// PKIWrappedKeyImportAPIResponse mirrors the fields Vault returns from
// POST /:mount/keys/import.
type PKIWrappedKeyImportAPIResponse struct {
	KeyID   string `json:"key_id"   mapstructure:"key_id"`
	KeyName string `json:"key_name" mapstructure:"key_name"`
	KeyType string `json:"key_type" mapstructure:"key_type"`
}

func (r *PKIWrappedKeyImportResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_secret_backend_wrapped_key_import"
}

func (r *PKIWrappedKeyImportResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Imports a BYOK-wrapped CA private key into a PKI secrets engine mount. " +
			"This is a write-only trigger resource: Create calls `POST /:mount/keys/import` and records " +
			"the resulting `key_id` in Terraform state. There is no BYOK-specific Read or Delete endpoint — " +
			"the imported key becomes a standard PKI key once created. Destroying this resource removes it " +
			"from Terraform state only; the key itself is not deleted from Vault.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Description: "Path of the destination PKI secrets engine mount.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_name": schema.StringAttribute{
				Description: "Optional human-readable name for the imported key in Vault.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"wrapped_key": schema.StringAttribute{
				Description: "Base64-encoded wrapped CA private key blob produced by " +
					"`vault_pki_secret_backend_ca_key_export`. Write-only — sent to Vault " +
					"on create and never stored in Terraform state.",
				Required:  true,
				Sensitive: true,
				WriteOnly: true,
			},
			"export_key_hmac": schema.StringAttribute{
				Description: `HMAC fingerprint of the wrapping key used to encrypt the blob ` +
					`(format "sha256:<hex>"). Write-only — used to identify the wrapping key ` +
					`for decryption and not stored in state after create. Obtain from ` +
					"`vault_pki_secret_backend_export_key.export_key_hmac`.",
				Required:  true,
				WriteOnly: true,
			},
			"key_id": schema.StringAttribute{
				Description: "UUID assigned by Vault to the imported key.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key_type": schema.StringAttribute{
				Description: `Key algorithm type as reported by Vault after import (e.g. "rsa", "ec", "ed25519").`,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

// Create calls POST /:mount/keys/import with wrapped_key + export_key_hmac.
// Vault decrypts the blob using the export key identified by export_key_hmac
// and imports the CA private key. The response contains key_id and key_type
// which are stored in Terraform state for reference.
func (r *PKIWrappedKeyImportResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// plan holds computed fields (key_id, key_type, key_name, mount, namespace).
	// config holds write-only fields (wrapped_key, export_key_hmac) which are
	// only available from the raw config, not from plan state.
	var plan PKIWrappedKeyImportModel
	var config PKIWrappedKeyImportModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	body := map[string]any{
		"wrapped_key":     config.WrappedKey.ValueString(),
		"export_key_hmac": config.ExportKeyHMAC.ValueString(),
	}
	if !plan.KeyName.IsNull() && !plan.KeyName.IsUnknown() && plan.KeyName.ValueString() != "" {
		body["key_name"] = plan.KeyName.ValueString()
	}

	vaultResp, err := vaultClient.Logical().WriteWithContext(ctx, r.importPath(plan.Mount.ValueString()), body)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}
	if vaultResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	if diags := r.populateModel(&plan, vaultResp); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read is a no-op. The import endpoint is write-only — Vault has no
// BYOK-specific read path for an imported key. State is preserved as written
// by Create.
func (r *PKIWrappedKeyImportResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

// Update is required by the resource.Resource interface but will never be
// called — every user-settable field is RequiresReplace.
func (r *PKIWrappedKeyImportResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

// Delete removes the resource from Terraform state only. The imported CA key
// in Vault is not deleted — there is no BYOK-specific delete endpoint. The
// key's lifecycle in Vault is managed as a standard PKI key independently.
func (r *PKIWrappedKeyImportResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// populateModel decodes the POST /keys/import response into the model.
func (r *PKIWrappedKeyImportResource) populateModel(data *PKIWrappedKeyImportModel, vaultResp *api.Secret) diag.Diagnostics {
	if vaultResp == nil || vaultResp.Data == nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil.")}
	}

	var apiResp PKIWrappedKeyImportAPIResponse
	if err := model.ToAPIModel(vaultResp.Data, &apiResp); err != nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Unable to decode Vault response", err.Error())}
	}

	data.KeyID = types.StringValue(apiResp.KeyID)
	data.KeyType = types.StringValue(apiResp.KeyType)
	if apiResp.KeyName != "" {
		data.KeyName = types.StringValue(apiResp.KeyName)
	} else {
		data.KeyName = types.StringNull()
	}

	return nil
}

// importPath builds POST /:mount/keys/import
func (r *PKIWrappedKeyImportResource) importPath(mount string) string {
	return fmt.Sprintf("%s/keys/import", mount)
}
