// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	vaultclient "github.com/hashicorp/vault/api"
)

var (
	_ resource.Resource                = &TransitKeyImportResource{}
	_ resource.ResourceWithConfigure   = &TransitKeyImportResource{}
	_ resource.ResourceWithImportState = &TransitKeyImportResource{}
)

// NewTransitKeyImportResource returns the implementation for this resource.
func NewTransitKeyImportResource() resource.Resource {
	return &TransitKeyImportResource{}
}

// TransitKeyImportResource manages importing external key material into a Vault Transit secrets engine.
// The resource model combines parameters for both initial key import (/keys/:name/import)
// and ongoing key configuration (/keys/:name/config) so an imported key's lifecycle can be managed
// within a single Terraform resource.
type TransitKeyImportResource struct {
	base.ResourceWithConfigure
}

// TransitKeyImportModel describes the Terraform resource data model.
type TransitKeyImportModel struct {
	base.BaseModel

	// Identifier and immutable import parameters (POST /keys/:name/import - ForceNew)
	Mount         types.String `tfsdk:"mount"`
	Name          types.String `tfsdk:"name"`
	Type          types.String `tfsdk:"type"`
	Ciphertext    types.String `tfsdk:"ciphertext"`
	PublicKey     types.String `tfsdk:"public_key"`
	HashFunction  types.String `tfsdk:"hash_function"`
	AllowRotation types.Bool   `tfsdk:"allow_rotation"`
	Derived       types.Bool   `tfsdk:"derived"`
	Context       types.String `tfsdk:"context"`

	// Tunable key configuration (POST /keys/:name/config - Update in place)
	DeletionAllowed      types.Bool  `tfsdk:"deletion_allowed"`
	Exportable           types.Bool  `tfsdk:"exportable"`
	AllowPlaintextBackup types.Bool  `tfsdk:"allow_plaintext_backup"`
	AutoRotatePeriod     types.Int64 `tfsdk:"auto_rotate_period"`
	MinDecryptionVersion types.Int64 `tfsdk:"min_decryption_version"`
	MinEncryptionVersion types.Int64 `tfsdk:"min_encryption_version"`

	// Read-only key metadata (GET /keys/:name - Computed)
	MinAvailableVersion      types.Int64  `tfsdk:"min_available_version"`
	ImportedKey              types.Bool   `tfsdk:"imported_key"`
	ImportedKeyAllowRotation types.Bool   `tfsdk:"imported_key_allow_rotation"`
	LatestVersion            types.Int64  `tfsdk:"latest_version"`
	LatestVersionType        types.String `tfsdk:"latest_version_type"`
	SupportsEncryption       types.Bool   `tfsdk:"supports_encryption"`
	SupportsDecryption       types.Bool   `tfsdk:"supports_decryption"`
	SupportsDerivation       types.Bool   `tfsdk:"supports_derivation"`
	SupportsSigning          types.Bool   `tfsdk:"supports_signing"`
	Keys                     types.Map    `tfsdk:"keys"`
}

func (r *TransitKeyImportResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_transit_secret_backend_key_import"
}

func (r *TransitKeyImportResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Imports existing key material (BYOK) into a new transit-managed encryption key.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path where the Transit secret backend is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the encryption key to create.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldType: schema.StringAttribute{
				MarkdownDescription: "Specifies the type of key to create (e.g. `aes128-gcm96`, `aes256-gcm96`, `chacha20-poly1305`, `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `hmac`, `aes128-cmac`, `aes192-cmac`, `aes256-cmac`).",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldCiphertext: schema.StringAttribute{
				MarkdownDescription: "A base64-encoded string containing the wrapped ephemeral AES key and the encrypted key material. Required when importing private or symmetric keys.",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					stringvalidator.AtLeastOneOf(path.MatchRoot(consts.FieldPublicKey)),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldPublicKey: schema.StringAttribute{
				MarkdownDescription: "A plaintext PEM public key to be imported. This limits the operations available under this key to verification and encryption, depending on the key type and algorithm, as no private key is available.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.AtLeastOneOf(path.MatchRoot(consts.FieldCiphertext)),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldHashFunction: schema.StringAttribute{
				MarkdownDescription: "The hash function used for the RSA-OAEP step of creating the ciphertext (`SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`). Defaults to `SHA256`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("SHA256"),
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("SHA1", "SHA224", "SHA256", "SHA384", "SHA512"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldAllowRotation: schema.BoolAttribute{
				MarkdownDescription: "If set, the imported key can be rotated within Vault by using the rotate endpoint.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldDerived: schema.BoolAttribute{
				MarkdownDescription: "Specifies if key derivation is to be used.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldContext: schema.StringAttribute{
				MarkdownDescription: "A base64-encoded string providing a context for key derivation. Required if `derived` is true.",
				Optional:            true,
				Sensitive:           true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldDeletionAllowed: schema.BoolAttribute{
				MarkdownDescription: "Specifies if the key is allowed to be deleted.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldExportable: schema.BoolAttribute{
				MarkdownDescription: "Enables keys to be exportable. Once enabled, cannot be disabled.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldAllowPlaintextBackup: schema.BoolAttribute{
				MarkdownDescription: "If set, enables taking backup of named key in plaintext format. Once enabled, cannot be disabled.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldAutoRotatePeriod: schema.Int64Attribute{
				MarkdownDescription: "The period in seconds at which this key should be rotated automatically. Set to 0 to disable.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldMinDecryptionVersion: schema.Int64Attribute{
				MarkdownDescription: "Minimum key version to use for decryption.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldMinEncryptionVersion: schema.Int64Attribute{
				MarkdownDescription: "Minimum key version to use for encryption.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldMinAvailableVersion: schema.Int64Attribute{
				MarkdownDescription: "Minimum key version available for use.",
				Computed:            true,
			},
			consts.FieldImportedKey: schema.BoolAttribute{
				MarkdownDescription: "Whether the key was imported into Vault (as opposed to generated by Vault).",
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldImportedKeyAllowRotation: schema.BoolAttribute{
				MarkdownDescription: "Whether the imported key is configured to allow rotation.",
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldLatestVersion: schema.Int64Attribute{
				MarkdownDescription: "Latest key version in use in the keyring.",
				Computed:            true,
			},
			consts.FieldLatestVersionType: schema.StringAttribute{
				MarkdownDescription: "The key type of the latest key version in the keyring. Supported as of Vault 2.1.",
				Computed:            true,
			},
			consts.FieldSupportsEncryption: schema.BoolAttribute{
				MarkdownDescription: "Whether the key supports encryption.",
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldSupportsDecryption: schema.BoolAttribute{
				MarkdownDescription: "Whether the key supports decryption.",
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldSupportsDerivation: schema.BoolAttribute{
				MarkdownDescription: "Whether the key supports derivation.",
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldSupportsSigning: schema.BoolAttribute{
				MarkdownDescription: "Whether the key supports signing.",
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldKeys: schema.MapAttribute{
				MarkdownDescription: "List of key versions and metadata in the keyring.",
				Computed:            true,
				ElementType:         types.StringType,
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *TransitKeyImportResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan TransitKeyImportModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	body := map[string]any{
		"type": plan.Type.ValueString(),
	}

	if !plan.Ciphertext.IsNull() && !plan.Ciphertext.IsUnknown() && plan.Ciphertext.ValueString() != "" {
		body["ciphertext"] = plan.Ciphertext.ValueString()
	}
	if !plan.PublicKey.IsNull() && !plan.PublicKey.IsUnknown() && plan.PublicKey.ValueString() != "" {
		body["public_key"] = plan.PublicKey.ValueString()
	}
	if !plan.HashFunction.IsNull() && !plan.HashFunction.IsUnknown() {
		body["hash_function"] = plan.HashFunction.ValueString()
	}
	if !plan.AllowRotation.IsNull() && !plan.AllowRotation.IsUnknown() {
		body["allow_rotation"] = plan.AllowRotation.ValueBool()
	}
	if !plan.Derived.IsNull() && !plan.Derived.IsUnknown() {
		body["derived"] = plan.Derived.ValueBool()
	}
	if !plan.Context.IsNull() && !plan.Context.IsUnknown() && plan.Context.ValueString() != "" {
		body["context"] = plan.Context.ValueString()
	}
	if !plan.Exportable.IsNull() && !plan.Exportable.IsUnknown() {
		body["exportable"] = plan.Exportable.ValueBool()
	}
	if !plan.AllowPlaintextBackup.IsNull() && !plan.AllowPlaintextBackup.IsUnknown() {
		body["allow_plaintext_backup"] = plan.AllowPlaintextBackup.ValueBool()
	}
	if !plan.AutoRotatePeriod.IsNull() && !plan.AutoRotatePeriod.IsUnknown() && plan.AutoRotatePeriod.ValueInt64() > 0 {
		body["auto_rotate_period"] = plan.AutoRotatePeriod.ValueInt64()
	}

	mount := plan.Mount.ValueString()
	name := plan.Name.ValueString()

	if _, err := cli.Logical().WriteWithContext(ctx, importPath(mount, name), body); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Apply any additional config settings that are not handled by the /import endpoint
	configBody := map[string]any{}
	if !plan.DeletionAllowed.IsNull() && !plan.DeletionAllowed.IsUnknown() {
		configBody["deletion_allowed"] = plan.DeletionAllowed.ValueBool()
	}
	if !plan.MinDecryptionVersion.IsNull() && !plan.MinDecryptionVersion.IsUnknown() {
		configBody["min_decryption_version"] = plan.MinDecryptionVersion.ValueInt64()
	}
	if !plan.MinEncryptionVersion.IsNull() && !plan.MinEncryptionVersion.IsUnknown() {
		configBody["min_encryption_version"] = plan.MinEncryptionVersion.ValueInt64()
	}
	if len(configBody) > 0 {
		if _, err := cli.Logical().WriteWithContext(ctx, configPath(mount, name), configBody); err != nil {
			resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
			return
		}
	}

	found := r.readFromVault(ctx, cli, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TransitKeyImportResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state TransitKeyImportModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), state.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	found := r.readFromVault(ctx, cli, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if !found {
		tflog.Warn(ctx, "Transit key not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *TransitKeyImportResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan TransitKeyImportModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state TransitKeyImportModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := plan.Mount.ValueString()
	name := plan.Name.ValueString()

	// Build the /config request body. All config fields are Optional+Computed,
	// so we check if the value is set before sending it to Vault to update.
	configBody := map[string]any{}

	if !plan.MinDecryptionVersion.IsNull() && !plan.MinDecryptionVersion.IsUnknown() {
		configBody["min_decryption_version"] = plan.MinDecryptionVersion.ValueInt64()
	}
	if !plan.MinEncryptionVersion.IsNull() && !plan.MinEncryptionVersion.IsUnknown() {
		configBody["min_encryption_version"] = plan.MinEncryptionVersion.ValueInt64()
	}
	if !plan.DeletionAllowed.IsNull() && !plan.DeletionAllowed.IsUnknown() {
		configBody["deletion_allowed"] = plan.DeletionAllowed.ValueBool()
	}
	if !plan.AutoRotatePeriod.IsNull() && !plan.AutoRotatePeriod.IsUnknown() {
		configBody["auto_rotate_period"] = plan.AutoRotatePeriod.ValueInt64()
	}

	// Vault treats these flags as one-way: once enabled, they cannot be disabled.
	// But the API silently ignores attempts to set them to false, so reject that
	// change here rather than leave Terraform unable to apply the requested value.
	if !plan.Exportable.IsNull() && !plan.Exportable.IsUnknown() {
		if plan.Exportable.ValueBool() {
			configBody["exportable"] = true
		} else if state.Exportable.ValueBool() {
			resp.Diagnostics.AddError(
				"Cannot disable exportable",
				"'exportable' cannot be disabled once enabled on a key",
			)
			return
		}
	}

	if !plan.AllowPlaintextBackup.IsNull() && !plan.AllowPlaintextBackup.IsUnknown() {
		if plan.AllowPlaintextBackup.ValueBool() {
			configBody["allow_plaintext_backup"] = true
		} else if state.AllowPlaintextBackup.ValueBool() {
			resp.Diagnostics.AddError(
				"Cannot disable allow_plaintext_backup",
				"'allow_plaintext_backup' cannot be disabled once enabled on a key",
			)
			return
		}
	}

	if _, err := cli.Logical().WriteWithContext(ctx, configPath(mount, name), configBody); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	found := r.readFromVault(ctx, cli, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TransitKeyImportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state TransitKeyImportModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), state.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := state.Mount.ValueString()
	name := state.Name.ValueString()

	p := keyPath(mount, name)
	if _, err := cli.Logical().DeleteWithContext(ctx, p); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *TransitKeyImportResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount, name, err := parseTransitKeyID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}

	var data TransitKeyImportModel
	data.Mount = types.StringValue(mount)
	data.Name = types.StringValue(name)

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	found := r.readFromVault(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if !found {
		resp.Diagnostics.AddError("Resource not found", fmt.Sprintf("Transit key %q not found on mount %q", name, mount))
		return
	}

	// Only reject when Vault explicitly reports imported_key as false; if the
	// field is absent we can't tell, so allow the import.
	if !data.ImportedKey.IsNull() && !data.ImportedKey.IsUnknown() && !data.ImportedKey.ValueBool() {
		resp.Diagnostics.AddError(
			"Key was not imported into Vault",
			fmt.Sprintf("Transit key %q on mount %q was created by Vault (imported_key is false) and cannot be managed by "+
				"vault_transit_secret_backend_key_import. Use the vault_transit_secret_backend_key resource instead.", name, mount),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// readFromVault populates data from Vault. It returns false if the key does not
// exist (or on error, in which case diags contains the error).
func (r *TransitKeyImportResource) readFromVault(ctx context.Context, cli *vaultclient.Client, data *TransitKeyImportModel, diags *diag.Diagnostics) bool {
	mount := data.Mount.ValueString()
	name := data.Name.ValueString()

	secret, err := cli.Logical().ReadWithContext(ctx, keyPath(mount, name))
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return false
	}
	if secret == nil || secret.Data == nil {
		return false
	}

	if v, ok := secret.Data[consts.FieldType].(string); ok {
		data.Type = types.StringValue(v)
	}
	if v, ok := secret.Data[consts.FieldDeletionAllowed].(bool); ok {
		data.DeletionAllowed = types.BoolValue(v)
	} else if data.DeletionAllowed.IsUnknown() {
		data.DeletionAllowed = types.BoolValue(false)
	}
	if v, ok := secret.Data[consts.FieldExportable].(bool); ok {
		data.Exportable = types.BoolValue(v)
	} else if data.Exportable.IsUnknown() {
		data.Exportable = types.BoolValue(false)
	}
	if v, ok := secret.Data[consts.FieldAllowPlaintextBackup].(bool); ok {
		data.AllowPlaintextBackup = types.BoolValue(v)
	} else if data.AllowPlaintextBackup.IsUnknown() {
		data.AllowPlaintextBackup = types.BoolValue(false)
	}
	// Vault reports the key's rotation setting as imported_key_allow_rotation.
	// allow_rotation is the configurable input for the same setting, so both
	// attributes are populated from that single value.
	if v, ok := secret.Data[consts.FieldImportedKeyAllowRotation].(bool); ok {
		data.ImportedKeyAllowRotation = types.BoolValue(v)
		data.AllowRotation = types.BoolValue(v)
	} else {
		if data.ImportedKeyAllowRotation.IsUnknown() {
			data.ImportedKeyAllowRotation = types.BoolValue(false)
		}
		if data.AllowRotation.IsUnknown() || data.AllowRotation.IsNull() {
			data.AllowRotation = types.BoolValue(false)
		}
	}

	if v, ok := secret.Data[consts.FieldDerived].(bool); ok {
		data.Derived = types.BoolValue(v)
	} else if data.Derived.IsUnknown() {
		data.Derived = types.BoolValue(false)
	}

	if v, ok := secret.Data[consts.FieldImportedKey].(bool); ok {
		data.ImportedKey = types.BoolValue(v)
	} else if data.ImportedKey.IsUnknown() {
		data.ImportedKey = types.BoolValue(true)
	}
	if v, ok := secret.Data[consts.FieldSupportsEncryption].(bool); ok {
		data.SupportsEncryption = types.BoolValue(v)
	} else if data.SupportsEncryption.IsUnknown() {
		data.SupportsEncryption = types.BoolValue(false)
	}
	if v, ok := secret.Data[consts.FieldSupportsDecryption].(bool); ok {
		data.SupportsDecryption = types.BoolValue(v)
	} else if data.SupportsDecryption.IsUnknown() {
		data.SupportsDecryption = types.BoolValue(false)
	}
	if v, ok := secret.Data[consts.FieldSupportsDerivation].(bool); ok {
		data.SupportsDerivation = types.BoolValue(v)
	} else if data.SupportsDerivation.IsUnknown() {
		data.SupportsDerivation = types.BoolValue(false)
	}
	if v, ok := secret.Data[consts.FieldSupportsSigning].(bool); ok {
		data.SupportsSigning = types.BoolValue(v)
	} else if data.SupportsSigning.IsUnknown() {
		data.SupportsSigning = types.BoolValue(false)
	}

	if v := util.Int64ValueOrNull(secret.Data[consts.FieldLatestVersion]); !v.IsNull() {
		data.LatestVersion = v
	} else if data.LatestVersion.IsUnknown() {
		data.LatestVersion = types.Int64Value(1)
	}

	if r.Meta().IsAPISupported(provider.VaultVersion210) {
		if v, ok := secret.Data[consts.FieldLatestVersionType].(string); ok && v != "" {
			data.LatestVersionType = types.StringValue(v)
		} else if data.LatestVersionType.IsUnknown() {
			data.LatestVersionType = types.StringNull()
		}
	} else if data.LatestVersionType.IsUnknown() {
		data.LatestVersionType = types.StringNull()
	}

	if v := util.Int64ValueOrNull(secret.Data[consts.FieldMinAvailableVersion]); !v.IsNull() {
		data.MinAvailableVersion = v
	} else if data.MinAvailableVersion.IsUnknown() {
		data.MinAvailableVersion = types.Int64Value(0)
	}
	if v := util.Int64ValueOrNull(secret.Data[consts.FieldMinDecryptionVersion]); !v.IsNull() {
		data.MinDecryptionVersion = v
	} else if data.MinDecryptionVersion.IsUnknown() {
		data.MinDecryptionVersion = types.Int64Value(1)
	}
	if v := util.Int64ValueOrNull(secret.Data[consts.FieldMinEncryptionVersion]); !v.IsNull() {
		data.MinEncryptionVersion = v
	} else if data.MinEncryptionVersion.IsUnknown() {
		data.MinEncryptionVersion = types.Int64Value(0)
	}
	if v := util.Int64ValueOrNull(secret.Data[consts.FieldAutoRotatePeriod]); !v.IsNull() {
		data.AutoRotatePeriod = v
	} else if data.AutoRotatePeriod.IsUnknown() {
		data.AutoRotatePeriod = types.Int64Value(0)
	}

	if rawKeys, ok := secret.Data[consts.FieldKeys].(map[string]any); ok {
		keysMap := make(map[string]string, len(rawKeys))
		for k, v := range rawKeys {
			if s, ok := v.(string); ok {
				keysMap[k] = s
			} else {
				b, err := json.Marshal(v)
				if err == nil {
					keysMap[k] = string(b)
				} else {
					keysMap[k] = fmt.Sprintf("%v", v)
				}
			}
		}
		mapVal, d := types.MapValueFrom(ctx, types.StringType, keysMap)
		if !d.HasError() {
			data.Keys = mapVal
		}
	} else if data.Keys.IsNull() || data.Keys.IsUnknown() {
		data.Keys = types.MapNull(types.StringType)
	}

	return true
}
