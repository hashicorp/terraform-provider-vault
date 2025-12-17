// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &ManagedKeysResource{}
var _ resource.ResourceWithConfigValidators = &ManagedKeysResource{}

// NewManagedKeysResource returns the implementation for the managed_keys resource
func NewManagedKeysResource() resource.Resource { return &ManagedKeysResource{} }

// ManagedKeysResource implements the resource
type ManagedKeysResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// Models
type ManagedKeyEntry struct {
	Name types.String `tfsdk:"name"`
	// Value-mapped fields are flexible; use a generic map for API mapping
	// Additional typed attributes can be added here if needed
}

type ManagedKeysModel struct {
	base.BaseModelLegacy

	AWS   types.List `tfsdk:"aws"`
	Azure types.List `tfsdk:"azure"`
	PKCS  types.List `tfsdk:"pkcs"`
}

// Metadata sets the resource type name
func (r *ManagedKeysResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_managed_keys"
}

func (r *ManagedKeysResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	var cv []resource.ConfigValidator
	return cv
}

// Schema defines the resource schema using nested blocks for aws/azure/pkcs
func (r *ManagedKeysResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: make(map[string]schema.Attribute),
		Blocks: map[string]schema.Block{
			"aws": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"name":       schema.StringAttribute{Required: true},
					"access_key": schema.StringAttribute{Optional: true, Sensitive: true},
					"secret_key": schema.StringAttribute{Optional: true, Sensitive: true},
					"curve":      schema.StringAttribute{Optional: true},
					"endpoint":   schema.StringAttribute{Optional: true},
					"key_bits":   schema.StringAttribute{Optional: true},
					"key_type":   schema.StringAttribute{Required: true},
					"kms_key":    schema.StringAttribute{Required: true},
					"region":     schema.StringAttribute{Optional: true, Computed: true},
				}},
			},
			"azure": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"name":          schema.StringAttribute{Required: true},
					"tenant_id":     schema.StringAttribute{Required: true},
					"client_id":     schema.StringAttribute{Required: true},
					"client_secret": schema.StringAttribute{Required: true, Sensitive: true},
					"environment":   schema.StringAttribute{Optional: true, Computed: true},
					"vault_name":    schema.StringAttribute{Required: true},
					"key_name":      schema.StringAttribute{Required: true},
					"resource":      schema.StringAttribute{Optional: true, Computed: true},
					"key_bits":      schema.StringAttribute{Optional: true},
					"key_type":      schema.StringAttribute{Required: true},
				}},
			},
			"pkcs": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"name":    schema.StringAttribute{Required: true},
					"library": schema.StringAttribute{Required: true},
					"key_label": schema.StringAttribute{Optional: true,
						Validators: []validator.String{stringvalidator.AtLeastOneOf(
							path.MatchRelative().AtParent().AtName("key_id"),
						)},
					},
					"key_id":           schema.StringAttribute{Optional: true},
					"mechanism":        schema.StringAttribute{Required: true},
					"pin":              schema.StringAttribute{Required: true, Sensitive: true},
					"slot":             schema.StringAttribute{Optional: true},
					"token_label":      schema.StringAttribute{Optional: true},
					"curve":            schema.StringAttribute{Optional: true},
					"key_bits":         schema.StringAttribute{Optional: true},
					"force_rw_session": schema.StringAttribute{Optional: true},
				}},
			},
		},
		MarkdownDescription: "Provides a resource to manage Managed Keys.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// helper: build map[string]interface{} for a nested block object
func buildMapFromAttrList(ctx context.Context, list types.List) ([]map[string]any, diag.Diagnostics) {
	if list.IsNull() || list.IsUnknown() {
		return nil, nil
	}

	var d diag.Diagnostics

	var elems []map[string]any
	for _, elem := range list.Elements() {
		v, err := elem.ToTerraformValue(ctx)
		if err != nil {
			d.AddError(errutil.ClientConfigureErr(err))
			return nil, d
		}
		e := map[string]tftypes.Value{}
		if err := v.As(&e); err != nil {
			d.AddError(errutil.ClientConfigureErr(err))
			return nil, d
		}
		sm := map[string]any{}
		for k, v := range e {
			var s string
			if v.IsNull() {
				continue
			}
			if err := v.As(&s); err != nil {
				d.AddError(errutil.ClientConfigureErr(err))
				return nil, d
			}
			sm[k] = s
		}
		elems = append(elems, sm)
	}

	return elems, nil
}

func (r *ManagedKeysResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ManagedKeysModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// write entries for each block type
	if !data.AWS.IsNull() {
		awsEntries, diags := buildMapFromAttrList(ctx, data.AWS)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, ent := range awsEntries {
			name := ent["name"].(string)
			path := fmt.Sprintf("sys/managed-keys/awskms/%s", name)
			log.Printf("[DEBUG] Writing AWS managed key to %s", path)
			if _, err := cli.Logical().WriteWithContext(ctx, path, ent); err != nil {
				resp.Diagnostics.AddError("Vault write error", err.Error())
				return
			}
		}
	}

	if !data.PKCS.IsNull() {
		pkcsEntries, diags := buildMapFromAttrList(ctx, data.PKCS)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, ent := range pkcsEntries {
			name := ent["name"].(string)
			path := fmt.Sprintf("sys/managed-keys/pkcs11/%s", name)
			log.Printf("[DEBUG] Writing PKCS managed key to %s", path)
			if _, err := cli.Logical().WriteWithContext(ctx, path, ent); err != nil {
				resp.Diagnostics.AddError("Vault write error", err.Error())
				return
			}
		}
	}

	if !data.Azure.IsNull() {
		azureEntries, diags := buildMapFromAttrList(ctx, data.Azure)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, ent := range azureEntries {
			name := ent["name"].(string)
			path := fmt.Sprintf("sys/managed-keys/azurekeyvault/%s", name)
			log.Printf("[DEBUG] Writing Azure managed key to %s", path)
			if _, err := cli.Logical().WriteWithContext(ctx, path, ent); err != nil {
				resp.Diagnostics.AddError("Vault write error", err.Error())
				return
			}
		}
	}

	// write ID default for backwards compatibility
	data.ID = types.StringValue("default")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ManagedKeysResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ManagedKeysModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// For each type, list keys and read each one, then populate state lists
	// AWS
	awsList := []map[string]interface{}{}
	if respList, err := cli.Logical().ListWithContext(ctx, "sys/managed-keys/awskms"); err == nil && respList != nil {
		if v, ok := respList.Data["keys"]; ok {
			for _, n := range v.([]interface{}) {
				name := n.(string)
				path := fmt.Sprintf("sys/managed-keys/awskms/%s", name)
				readResp, err := cli.Logical().ReadWithContext(ctx, path)
				if err != nil || readResp == nil {
					continue
				}
				m := map[string]interface{}{}
				for k, val := range readResp.Data {
					m[k] = val
				}
				// include name
				m["name"] = name
				awsList = append(awsList, m)
			}
		}
	}

	// PKCS
	pkcsList := []map[string]interface{}{}
	if respList, err := cli.Logical().ListWithContext(ctx, "sys/managed-keys/pkcs11"); err == nil && respList != nil {
		if v, ok := respList.Data["keys"]; ok {
			for _, n := range v.([]interface{}) {
				name := n.(string)
				path := fmt.Sprintf("sys/managed-keys/pkcs11/%s", name)
				readResp, err := cli.Logical().ReadWithContext(ctx, path)
				if err != nil || readResp == nil {
					continue
				}
				m := map[string]interface{}{}
				for k, val := range readResp.Data {
					m[k] = val
				}
				m["name"] = name
				pkcsList = append(pkcsList, m)
			}
		}
	}

	// Azure
	azureList := []map[string]interface{}{}
	if respList, err := cli.Logical().ListWithContext(ctx, "sys/managed-keys/azurekeyvault"); err == nil && respList != nil {
		if v, ok := respList.Data["keys"]; ok {
			for _, n := range v.([]interface{}) {
				name := n.(string)
				path := fmt.Sprintf("sys/managed-keys/azurekeyvault/%s", name)
				readResp, err := cli.Logical().ReadWithContext(ctx, path)
				if err != nil || readResp == nil {
					continue
				}
				m := map[string]interface{}{}
				for k, val := range readResp.Data {
					m[k] = val
				}
				m["name"] = name
				azureList = append(azureList, m)
			}
		}
	}

	// Convert to types and set on data
	if val, diags := types.ListValueFrom(ctx, types.MapType{ElemType: types.StringType}, awsList); diags.HasError() {
		resp.Diagnostics.Append(diags...)
	} else {
		data.AWS = val
	}
	if val, diags := types.ListValueFrom(ctx, types.MapType{ElemType: types.StringType}, pkcsList); diags.HasError() {
		resp.Diagnostics.Append(diags...)
	} else {
		data.PKCS = val
	}
	if val, diags := types.ListValueFrom(ctx, types.MapType{ElemType: types.StringType}, azureList); diags.HasError() {
		resp.Diagnostics.Append(diags...)
	} else {
		data.Azure = val
	}

	data.ID = types.StringValue("default")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ManagedKeysResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ManagedKeysModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// For simplicity, rewrite all entries similar to Create

	// --- Write aws entries ---
	if !data.AWS.IsNull() {
		awsEntries, diags := buildMapFromAttrList(ctx, data.AWS)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, ent := range awsEntries {
			name := ent["name"].(string)
			path := fmt.Sprintf("sys/managed-keys/awskms/%s", name)
			if _, err := cli.Logical().WriteWithContext(ctx, path, ent); err != nil {
				resp.Diagnostics.AddError("Vault write error", err.Error())
				return
			}
		}
	}

	// PKCS
	if !data.PKCS.IsNull() {
		pkcsEntries, diags := buildMapFromAttrList(ctx, data.PKCS)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, ent := range pkcsEntries {
			name := ent["name"].(string)
			path := fmt.Sprintf("sys/managed-keys/pkcs11/%s", name)
			if _, err := cli.Logical().WriteWithContext(ctx, path, ent); err != nil {
				resp.Diagnostics.AddError("Vault write error", err.Error())
				return
			}
		}
	}

	// Azure
	if !data.Azure.IsNull() {
		azureEntries, diags := buildMapFromAttrList(ctx, data.Azure)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, ent := range azureEntries {
			name := ent["name"].(string)
			path := fmt.Sprintf("sys/managed-keys/azurekeyvault/%s", name)
			if _, err := cli.Logical().WriteWithContext(ctx, path, ent); err != nil {
				resp.Diagnostics.AddError("Vault write error", err.Error())
				return
			}
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ManagedKeysResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ManagedKeysModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// delete all keys of each type
	// AWS
	if respList, err := cli.Logical().ListWithContext(ctx, "sys/managed-keys/awskms"); err == nil && respList != nil {
		if v, ok := respList.Data["keys"]; ok {
			for _, n := range v.([]interface{}) {
				name := n.(string)
				cli.Logical().DeleteWithContext(ctx, fmt.Sprintf("sys/managed-keys/awskms/%s", name))
			}
		}
	}

	// PKCS
	if respList, err := cli.Logical().ListWithContext(ctx, "sys/managed-keys/pkcs11"); err == nil && respList != nil {
		if v, ok := respList.Data["keys"]; ok {
			for _, n := range v.([]interface{}) {
				name := n.(string)
				cli.Logical().DeleteWithContext(ctx, fmt.Sprintf("sys/managed-keys/pkcs11/%s", name))
			}
		}
	}

	// Azure
	if respList, err := cli.Logical().ListWithContext(ctx, "sys/managed-keys/azurekeyvault"); err == nil && respList != nil {
		if v, ok := respList.Data["keys"]; ok {
			for _, n := range v.([]interface{}) {
				name := n.(string)
				cli.Logical().DeleteWithContext(ctx, fmt.Sprintf("sys/managed-keys/azurekeyvault/%s", name))
			}
		}
	}
}
