// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package generic

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &GenericEndpointEphemeralResource{}

// NewGenericEndpointEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewGenericEndpointEphemeralResource = func() ephemeral.EphemeralResource {
	return &GenericEndpointEphemeralResource{}
}

// GenericEndpointEphemeralResource implements the methods that define this resource
type GenericEndpointEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// GenericEndpointEphemeralModel describes the Terraform resource data model to match the
// resource schema.
type GenericEndpointEphemeralModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Path          types.String `tfsdk:"path"`
	DataJSON      types.String `tfsdk:"data_json"`
	WriteFields   types.List   `tfsdk:"write_fields"`
	WriteDataJSON types.String `tfsdk:"write_data_json"`
	WriteData     types.Map    `tfsdk:"write_data"`
	// Naming convention check: path_wrap_ttl is the standard for Generic endpoints
	PathWrapTTL types.String `tfsdk:"path_wrap_ttl"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
func (r *GenericEndpointEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				MarkdownDescription: "Full path to the Vault endpoint that will be written",
				Required:            true,
			},
			consts.FieldDataJSON: schema.StringAttribute{
				MarkdownDescription: "JSON-encoded data to write.",
				Required:            true,
				Sensitive:           true,
			},
			consts.FieldWriteFields: schema.ListAttribute{
				MarkdownDescription: "Top-level fields returned by write to persist in state",
				ElementType:         types.StringType,
				Optional:            true,
			},
			consts.FieldWriteDataJSON: schema.StringAttribute{
				MarkdownDescription: "JSON data returned by write operation",
				Computed:            true,
			},
			consts.FieldWriteData: schema.MapAttribute{
				MarkdownDescription: "Map of strings returned by write operation",
				ElementType:         types.StringType,
				Computed:            true,
			},
			consts.FieldPathWrapTTL: schema.StringAttribute{
				MarkdownDescription: "The TTL for the wrapped response.",
				Optional:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to write to a generic Vault endpoint and read response data.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *GenericEndpointEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_generic_endpoint"
}

func (r *GenericEndpointEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GenericEndpointEphemeralModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Parse the JSON data
	var requestData map[string]interface{}
	err = json.Unmarshal([]byte(data.DataJSON.ValueString()), &requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid JSON",
			fmt.Sprintf("data_json syntax error: %s", err),
		)
		return
	}

	path := data.Path.ValueString()

	// Set wrap TTL if provided
	if !data.PathWrapTTL.IsNull() && !data.PathWrapTTL.IsUnknown() {
		c.SetWrappingLookupFunc(func(operation, path string) string {
			return data.PathWrapTTL.ValueString()
		})
		// Clean up so subsequent operations aren't accidentally wrapped
		defer c.SetWrappingLookupFunc(nil)
	}

	// Write to Vault using WriteWithContext which properly handles POST for auth endpoints
	response, err := c.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Writing to Vault",
			fmt.Sprintf("error writing to %s: %s", path, err),
		)
		return
	}

	// Process write_fields if provided
	writeDataMap := make(map[string]string)
	writeData := make(map[string]interface{})

	// Prepare wrap info map if present
	var wrapMap map[string]interface{}
	if response != nil && response.WrapInfo != nil {
		if wb, err := json.Marshal(response.WrapInfo); err == nil {
			_ = json.Unmarshal(wb, &wrapMap)
		}
	}

	// Prepare auth map if present
	var authMap map[string]interface{}
	if response != nil && response.Auth != nil {
		if ab, err := json.Marshal(response.Auth); err == nil {
			_ = json.Unmarshal(ab, &authMap)
		}
	}

	if response != nil && (response.Data != nil || wrapMap != nil || authMap != nil || response.LeaseDuration != 0 || response.LeaseID != "") {
		// Get write_fields list
		var writeFields []string
		if !data.WriteFields.IsNull() && !data.WriteFields.IsUnknown() {
			resp.Diagnostics.Append(data.WriteFields.ElementsAs(ctx, &writeFields, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		for _, writeField := range writeFields {
			// 1) initial check for response.Data
			if response.Data != nil {
				if v, ok := response.Data[writeField]; ok {
					writeData[writeField] = v
					if vs, ok := v.(string); ok {
						writeDataMap[writeField] = vs
					} else {
						vBytes, _ := json.Marshal(v)
						writeDataMap[writeField] = string(vBytes)
					}
					continue
				}
			}

			// 2) "wrap_info" to include the entire wrap map
			if writeField == "wrap_info" && wrapMap != nil {
				writeData[writeField] = wrapMap
				vBytes, _ := json.Marshal(wrapMap)
				writeDataMap[writeField] = string(vBytes)
				continue
			}

			// 3) checking individual fields in WrapInfo
			if wrapMap != nil {
				if v, ok := wrapMap[writeField]; ok {
					writeData[writeField] = v
					if vs, ok := v.(string); ok {
						writeDataMap[writeField] = vs
					} else {
						vBytes, _ := json.Marshal(v)
						writeDataMap[writeField] = string(vBytes)
					}
					continue
				}
			}

			// 4) "auth" to include the entire auth map
			if writeField == "auth" && authMap != nil {
				writeData[writeField] = authMap
				vBytes, _ := json.Marshal(authMap)
				writeDataMap[writeField] = string(vBytes)
				continue
			}

			// 5) checking individual fields in Auth
			if authMap != nil {
				if v, ok := authMap[writeField]; ok {
					writeData[writeField] = v
					if vs, ok := v.(string); ok {
						writeDataMap[writeField] = vs
					} else {
						vBytes, _ := json.Marshal(v)
						writeDataMap[writeField] = string(vBytes)
					}
					continue
				}

				// alias: "token" -> "client_token" in Auth
				if writeField == "token" {
					if v, ok := authMap["client_token"]; ok {
						writeData[writeField] = v
						if vs, ok := v.(string); ok {
							writeDataMap[writeField] = vs
						} else {
							vBytes, _ := json.Marshal(v)
							writeDataMap[writeField] = string(vBytes)
						}
						continue
					}
				}
			}

			// 6) check top-level response fields (lease_duration, lease_id, renewable)
			topLevel := map[string]interface{}{
				"lease_duration": response.LeaseDuration,
				"lease_id":       response.LeaseID,
				"renewable":      response.Renewable,
			}
			if v, ok := topLevel[writeField]; ok {
				writeData[writeField] = v
				if vs, ok := v.(string); ok {
					writeDataMap[writeField] = vs
				} else {
					vBytes, _ := json.Marshal(v)
					writeDataMap[writeField] = string(vBytes)
				}
				continue
			}
		}

		jsonData, err := json.Marshal(writeData)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Marshaling JSON",
				fmt.Sprintf("error marshaling JSON for %q: %s", path, err),
			)
			return
		}
		data.WriteDataJSON = types.StringValue(string(jsonData))
	} else {
		data.WriteDataJSON = types.StringValue("null")
	}

	// Convert writeDataMap to types.Map
	writeDataMapTF := make(map[string]types.String)
	for k, v := range writeDataMap {
		writeDataMapTF[k] = types.StringValue(v)
	}
	mapValue, diags := types.MapValueFrom(ctx, types.StringType, writeDataMapTF)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.WriteData = mapValue

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
