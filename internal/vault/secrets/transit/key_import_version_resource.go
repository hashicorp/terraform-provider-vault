// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/util"
)

var (
	_ resource.Resource                = &TransitKeyImportVersionResource{}
	_ resource.ResourceWithConfigure   = &TransitKeyImportVersionResource{}
	_ resource.ResourceWithImportState = &TransitKeyImportVersionResource{}
)

// NewTransitKeyImportVersionResource returns the implementation for this resource.
func NewTransitKeyImportVersionResource() resource.Resource {
	return &TransitKeyImportVersionResource{}
}

// TransitKeyImportVersionResource imports new key material into an existing Transit key.
type TransitKeyImportVersionResource struct {
	base.ResourceWithConfigure
}

// TransitKeyImportVersionModel describes the Terraform resource data model.
type TransitKeyImportVersionModel struct {
	base.BaseModel

	Mount               types.String `tfsdk:"mount"`
	KeyName             types.String `tfsdk:"key_name"`
	CiphertextWO        types.String `tfsdk:"ciphertext_wo"`
	CiphertextWOVersion types.Int64  `tfsdk:"ciphertext_wo_version"`
	PublicKey           types.String `tfsdk:"public_key"`
	HashFunction        types.String `tfsdk:"hash_function"`
	Version             types.Int64  `tfsdk:"version"`
}

func (r *TransitKeyImportVersionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_transit_secret_backend_key_import_version"
}

func (r *TransitKeyImportVersionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Imports new key material into an existing imported Transit encryption key.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path where the Transit secret backend is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeyName: schema.StringAttribute{
				MarkdownDescription: "Name of the existing Transit encryption key to import key material into.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldCiphertextWO: schema.StringAttribute{
				MarkdownDescription: "A base64-encoded string containing the wrapped ephemeral AES key and the encrypted key material (write-only). Required when importing private or symmetric keys. Must be used together with ciphertext_wo_version.",
				Optional:            true,
				Sensitive:           true,
				WriteOnly:           true,
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot(consts.FieldCiphertextWOVersion)),
				},
			},
			consts.FieldCiphertextWOVersion: schema.Int64Attribute{
				MarkdownDescription: "Version identifier for ciphertext updates. Increment to trigger a new key version import. Must be used together with ciphertext_wo.",
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.AlsoRequires(path.MatchRoot(consts.FieldCiphertextWO)),
				},
			},
			consts.FieldPublicKey: schema.StringAttribute{
				MarkdownDescription: "A plaintext PEM public key to be imported.",
				Optional:            true,
			},
			consts.FieldHashFunction: schema.StringAttribute{
				MarkdownDescription: "The hash function used for the RSA-OAEP step of creating the ciphertext (`SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`). Defaults to `SHA256`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("SHA256"),
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("SHA1", "SHA224", "SHA256", "SHA384", "SHA512"),
				},
			},
			consts.FieldVersion: schema.Int64Attribute{
				MarkdownDescription: "Key version to update. If omitted, a new key version will be created.",
				Optional:            true,
				Computed:            true,
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *TransitKeyImportVersionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan TransitKeyImportVersionModel
	var config TransitKeyImportVersionModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasCiphertext := !config.CiphertextWO.IsNull() && !config.CiphertextWO.IsUnknown() && config.CiphertextWO.ValueString() != ""
	hasPublicKey := !plan.PublicKey.IsNull() && !plan.PublicKey.IsUnknown() && plan.PublicKey.ValueString() != ""

	if !hasCiphertext && !hasPublicKey {
		resp.Diagnostics.AddError(
			"Missing key material",
			"Either 'ciphertext_wo' (for private/symmetric key import) or 'public_key' (for public key only import) must be provided.",
		)
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	body := map[string]any{}
	if hasCiphertext {
		body["ciphertext"] = config.CiphertextWO.ValueString()
	}
	if hasPublicKey {
		body["public_key"] = plan.PublicKey.ValueString()
	}
	if !plan.HashFunction.IsNull() && !plan.HashFunction.IsUnknown() {
		body["hash_function"] = plan.HashFunction.ValueString()
	}
	if !plan.Version.IsNull() && !plan.Version.IsUnknown() && plan.Version.ValueInt64() > 0 {
		body["version"] = plan.Version.ValueInt64()
	}

	mount := plan.Mount.ValueString()
	keyName := plan.KeyName.ValueString()
	p := importVersionPath(mount, keyName)

	if _, err := cli.Logical().WriteWithContext(ctx, p, body); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	if plan.Version.IsNull() || plan.Version.IsUnknown() {
		secret, err := cli.Logical().ReadWithContext(ctx, keyPath(mount, keyName))
		if err != nil {
			resp.Diagnostics.AddError(errutil.VaultReadErr(err))
			return
		}
		if secret != nil && secret.Data != nil {
			if lv := util.Int64ValueOrNull(secret.Data[consts.FieldLatestVersion]); !lv.IsNull() {
				plan.Version = lv
			} else {
				plan.Version = types.Int64Value(1)
			}
		} else {
			plan.Version = types.Int64Value(1)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TransitKeyImportVersionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state TransitKeyImportVersionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), state.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	secret, err := cli.Logical().ReadWithContext(ctx, keyPath(state.Mount.ValueString(), state.KeyName.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil || secret.Data == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *TransitKeyImportVersionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan TransitKeyImportVersionModel
	var config TransitKeyImportVersionModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasCiphertext := !config.CiphertextWO.IsNull() && !config.CiphertextWO.IsUnknown() && config.CiphertextWO.ValueString() != ""
	hasPublicKey := !plan.PublicKey.IsNull() && !plan.PublicKey.IsUnknown() && plan.PublicKey.ValueString() != ""

	if !hasCiphertext && !hasPublicKey {
		resp.Diagnostics.AddError(
			"Missing key material",
			"Either 'ciphertext_wo' (for private/symmetric key import) or 'public_key' (for public key only import) must be provided.",
		)
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	body := map[string]any{}
	if hasCiphertext {
		body["ciphertext"] = config.CiphertextWO.ValueString()
	}
	if hasPublicKey {
		body["public_key"] = plan.PublicKey.ValueString()
	}
	if !plan.HashFunction.IsNull() && !plan.HashFunction.IsUnknown() {
		body["hash_function"] = plan.HashFunction.ValueString()
	}
	if !plan.Version.IsNull() && !plan.Version.IsUnknown() && plan.Version.ValueInt64() > 0 {
		body["version"] = plan.Version.ValueInt64()
	}

	mount := plan.Mount.ValueString()
	keyName := plan.KeyName.ValueString()
	p := importVersionPath(mount, keyName)

	if _, err := cli.Logical().WriteWithContext(ctx, p, body); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	if plan.Version.IsNull() || plan.Version.IsUnknown() {
		secret, err := cli.Logical().ReadWithContext(ctx, keyPath(mount, keyName))
		if err != nil {
			resp.Diagnostics.AddError(errutil.VaultReadErr(err))
			return
		}
		if secret != nil && secret.Data != nil {
			if lv := util.Int64ValueOrNull(secret.Data[consts.FieldLatestVersion]); !lv.IsNull() {
				plan.Version = lv
			} else {
				plan.Version = types.Int64Value(1)
			}
		} else {
			plan.Version = types.Int64Value(1)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TransitKeyImportVersionResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Removing from state; key version remains in Vault keyring
}

func (r *TransitKeyImportVersionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount, keyName, version, err := parseTransitKeyVersionID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}

	var data TransitKeyImportVersionModel
	data.Mount = types.StringValue(mount)
	data.KeyName = types.StringValue(keyName)
	data.Version = types.Int64Value(version)

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	secret, err := cli.Logical().ReadWithContext(ctx, keyPath(mount, keyName))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil || secret.Data == nil {
		resp.Diagnostics.AddError("Resource not found", fmt.Sprintf("Transit key %q not found on mount %q", keyName, mount))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
