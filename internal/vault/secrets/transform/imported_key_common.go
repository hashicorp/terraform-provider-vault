// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	vaultclient "github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

// ImportedKeyCommonModel holds the fields shared by the tokenization and FPE imported key
// resources. It is embedded in each resource's model.
type ImportedKeyCommonModel struct {
	base.BaseModel

	// Identifier and immutable import parameters.
	Mount types.String `tfsdk:"mount"`
	Name  types.String `tfsdk:"name"`

	// Key material parameters. Since ciphertext is write-only, changes to that value
	// are triggered by updates to ciphertext_wo_version
	CiphertextWO        types.String `tfsdk:"ciphertext_wo"`
	CiphertextWOVersion types.Int64  `tfsdk:"ciphertext_wo_version"`
	HashFunction        types.String `tfsdk:"hash_function"`

	// Settings shared by both transformation types.
	AllowedRoles    types.List `tfsdk:"allowed_roles"`
	DeletionAllowed types.Bool `tfsdk:"deletion_allowed"`
}

// importedKeyCommonAttributes returns the schema attributes shared by both resources.
// ciphertext_wo_version is not included, because its behavior differs by type: only tokenization
// transformations can import new key versions. Each resource defines it, and must pair it with
// ciphertext_wo, which requires it.
func importedKeyCommonAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		consts.FieldMount: schema.StringAttribute{
			MarkdownDescription: "Path where the Transform secret backend is mounted. Changing this field replaces this resource.",
			Required:            true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},
		},
		consts.FieldName: schema.StringAttribute{
			MarkdownDescription: "Name of the transformation to create. Changing this field replaces this resource.",
			Required:            true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},
		},
		// This field AlsoRequires FieldCiphertextWOVersion, however each transform type differs in behavior so it is defined in each model separately.
		consts.FieldCiphertextWO: schema.StringAttribute{
			MarkdownDescription: "A base64-encoded string containing the wrapped ephemeral AES key and the encrypted 256-bit AES key material (write-only). Required with `ciphertext_wo_version`. Required to create the transformation, but may be omitted for a transformation adopted with `terraform import`.",
			Optional:            true,
			Sensitive:           true,
			WriteOnly:           true,
			Validators: []validator.String{
				stringvalidator.AlsoRequires(path.MatchRoot(consts.FieldCiphertextWOVersion)),
			},
		},
		consts.FieldHashFunction: schema.StringAttribute{
			MarkdownDescription: "The hash function used for the RSA-OAEP step of creating the ciphertext (`SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`). Vault uses `SHA256` if not set. Vault does not return this value, so it is not verified against the transformation.",
			Optional:            true,
			Validators: []validator.String{
				stringvalidator.OneOfCaseInsensitive("SHA1", "SHA224", "SHA256", "SHA384", "SHA512"),
			},
		},
		consts.FieldAllowedRoles: schema.ListAttribute{
			MarkdownDescription: "The list of roles allowed to perform this transformation.",
			Optional:            true,
			Computed:            true,
			ElementType:         types.StringType,
			PlanModifiers: []planmodifier.List{
				listplanmodifier.UseStateForUnknown(),
			},
		},
		consts.FieldDeletionAllowed: schema.BoolAttribute{
			MarkdownDescription: "If true, this transformation can be deleted. Deletion is blocked while this is false, so it must be applied as `true` before the resource can be destroyed. Vault's import endpoint does not accept this parameter, so it is applied in an update immediately after the key is imported.",
			Optional:            true,
			Computed:            true,
			PlanModifiers: []planmodifier.Bool{
				boolplanmodifier.UseStateForUnknown(),
			},
		},
	}
}

// importBody builds the shared part of the /import request body. ciphertext_wo is write-only, so it
// is only available from config.
func (m *ImportedKeyCommonModel) importBody(ctx context.Context, config *ImportedKeyCommonModel) (map[string]any, diag.Diagnostics) {
	body := map[string]any{}
	var diags diag.Diagnostics
	if !config.CiphertextWO.IsNull() && !config.CiphertextWO.IsUnknown() {
		body["ciphertext"] = config.CiphertextWO.ValueString()
	}
	if !m.HashFunction.IsNull() && !m.HashFunction.IsUnknown() {
		body["hash_function"] = m.HashFunction.ValueString()
	}
	if !m.AllowedRoles.IsNull() && !m.AllowedRoles.IsUnknown() {
		roles := make([]string, 0, len(m.AllowedRoles.Elements()))
		diags.Append(m.AllowedRoles.ElementsAs(ctx, &roles, false)...)
		if !diags.HasError() {
			body["allowed_roles"] = roles
		}
	}
	return body, diags
}

// updateBody builds the shared part of the request body for settings that can be updated in place.
func (m *ImportedKeyCommonModel) updateBody(ctx context.Context) (map[string]any, diag.Diagnostics) {
	body := map[string]any{}
	var diags diag.Diagnostics
	if !m.DeletionAllowed.IsNull() && !m.DeletionAllowed.IsUnknown() {
		body["deletion_allowed"] = m.DeletionAllowed.ValueBool()
	}
	if !m.AllowedRoles.IsNull() && !m.AllowedRoles.IsUnknown() {
		roles := make([]string, 0, len(m.AllowedRoles.Elements()))
		diags.Append(m.AllowedRoles.ElementsAs(ctx, &roles, false)...)
		if !diags.HasError() {
			body["allowed_roles"] = roles
		}
	}
	return body, diags
}

// setFromVault populates the shared fields from a transformation read from Vault.
func (m *ImportedKeyCommonModel) setFromVault(ctx context.Context, data map[string]any) diag.Diagnostics {
	var diags diag.Diagnostics

	if raw, ok := data[consts.FieldAllowedRoles]; ok && raw != nil {
		allowedRoles, d := types.ListValueFrom(ctx, types.StringType, raw)
		diags.Append(d...)
		if !d.HasError() {
			m.AllowedRoles = allowedRoles
		}
	} else if m.AllowedRoles.IsUnknown() {
		m.AllowedRoles = types.ListNull(types.StringType)
	}
	if v, ok := data[consts.FieldDeletionAllowed].(bool); ok {
		m.DeletionAllowed = types.BoolValue(v)
	}
	return diags
}

// readTransformation reads a transformation and returns its data. It returns nil data if the
// transformation does not exist, and an error if it exists with a different type than the
// resource manages.
func readTransformation(ctx context.Context, cli *vaultclient.Client, mount, name, wantType string) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	secret, err := cli.Logical().ReadWithContext(ctx, readPath(mount, name))
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return nil, diags
	}
	if secret == nil || secret.Data == nil {
		return nil, diags
	}
	if got, _ := secret.Data[consts.FieldType].(string); got != wantType {
		diags.AddError(
			"Unexpected transformation type",
			fmt.Sprintf("Transformation %q on mount %q has type %q, but this resource manages %q transformations.", name, mount, got, wantType),
		)
		return nil, diags
	}
	return secret.Data, diags
}

// importedKeyFromID builds the initial state for terraform import. Namespaced resources can only
// be imported by providing the namespace through an environment variable. It is persisted so the
// imported state matches the configuration.
func importedKeyFromID(id string) (ImportedKeyCommonModel, error) {
	parsed, err := parseTransformationID(id)
	if err != nil {
		return ImportedKeyCommonModel{}, err
	}

	var data ImportedKeyCommonModel
	data.Mount = types.StringValue(parsed.Mount)
	data.Name = types.StringValue(parsed.Name)
	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		data.Namespace = types.StringValue(ns)
	}
	return data, nil
}
