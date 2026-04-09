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
	Mount         types.String `tfsdk:"mount"`
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
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Full path to the Vault endpoint that will be written",
				Required:            true,
			},
			consts.FieldDataJSON: schema.StringAttribute{
				MarkdownDescription: "JSON-encoded data to write.",
				Required:            true,
				Sensitive:           true,
			},
			consts.FieldWriteFields: schema.ListAttribute{
				MarkdownDescription: "Top-level fields returned by the write operation to extract and expose via write_data/write_data_json",
				ElementType:         types.StringType,
				Optional:            true,
			},
			consts.FieldWriteDataJSON: schema.StringAttribute{
				MarkdownDescription: "JSON data returned by write operation",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldWriteData: schema.MapAttribute{
				MarkdownDescription: "Map of strings returned by write operation",
				ElementType:         types.StringType,
				Computed:            true,
				Sensitive:           true,
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

// addToWriteData is a helper function that adds a value to both writeData and writeDataMap.
// It handles string values directly and marshals non-string values to JSON.
func addToWriteData(writeData map[string]interface{}, writeDataMap map[string]string, field string, value interface{}) {
	writeData[field] = value
	if vs, ok := value.(string); ok {
		writeDataMap[field] = vs
	} else {
		vBytes, err := json.Marshal(value)
		if err != nil {
			// Fallback to a generic string representation if JSON marshalling fails.
			writeDataMap[field] = fmt.Sprintf("%v", value)
			return
		}
		writeDataMap[field] = string(vBytes)
	}
}

func (r *GenericEndpointEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GenericEndpointEphemeralModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
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

	path := data.Mount.ValueString()

	// Use a per-request client when wrap TTL is provided to avoid mutating the shared client.
	vc := vaultClient

	// Set wrap TTL if provided
	if !data.PathWrapTTL.IsNull() && !data.PathWrapTTL.IsUnknown() {
		vc, err = vaultClient.Clone()
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Configuring Vault Client",
				fmt.Sprintf("error cloning Vault client for wrapping configuration: %s", err),
			)
			return
		}

		vc.SetWrappingLookupFunc(func(operation, path string) string {
			return data.PathWrapTTL.ValueString()
		})
	}

	// Write to Vault using WriteWithContext which properly handles POST for auth endpoints
	response, err := vc.Logical().WriteWithContext(ctx, path, requestData)
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
			if err := json.Unmarshal(wb, &wrapMap); err != nil {
				resp.Diagnostics.AddWarning(
					"Failed to parse WrapInfo",
					fmt.Sprintf("Could not extract wrap_info fields: %s", err),
				)
			}
		}
	}

	// Prepare auth map if present
	var authMap map[string]interface{}
	if response != nil && response.Auth != nil {
		if ab, err := json.Marshal(response.Auth); err == nil {
			if err := json.Unmarshal(ab, &authMap); err != nil {
				resp.Diagnostics.AddWarning(
					"Failed to parse Auth",
					fmt.Sprintf("Could not extract auth fields: %s", err),
				)
			}
		}
	}

	if response != nil {
		// Get write_fields list
		var writeFields []string
		if !data.WriteFields.IsNull() && !data.WriteFields.IsUnknown() {
			resp.Diagnostics.Append(data.WriteFields.ElementsAs(ctx, &writeFields, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		foundFields := make(map[string]bool)
		for _, writeField := range writeFields {
			// 1) Check response.Data first - this is the primary data payload returned by most Vault endpoints.
			// It is always checked first for any write_field requested by the user.
			// As most Vault API responses return their data in the Data field (e.g., secret values, configuration).
			if response.Data != nil {
				if v, ok := response.Data[writeField]; ok {
					addToWriteData(writeData, writeDataMap, writeField, v)
					foundFields[writeField] = true
					continue
				}
			}

			// 2) Check for the  "wrap_info" field to return the entire WrapInfo object.
			// Checked when User explicitly requests "wrap_info" in write_fields and path_wrap_ttl was set.
			// When response wrapping is enabled, users may want the complete wrap metadata
			// (token, ttl, creation_time, etc.) as a single JSON object.
			if writeField == "wrap_info" && wrapMap != nil {
				addToWriteData(writeData, writeDataMap, writeField, wrapMap)
				foundFields[writeField] = true
				continue
			}

			// 3) Check for individual fields within WrapInfo (e.g., "token", "ttl", "creation_time").
			// Checked when User requests a specific WrapInfo field by name and path_wrap_ttl was set.
			// Allows extracting specific wrap metadata fields without needing the entire wrap_info object.
			// Common fields: token, ttl, creation_time, wrapped_accessor, creation_path.
			if wrapMap != nil {
				if v, ok := wrapMap[writeField]; ok {
					addToWriteData(writeData, writeDataMap, writeField, v)
					foundFields[writeField] = true
					continue
				}
			}

			// 4) Check for the special "auth" field to return the entire Auth object.
			// When User explicitly requests "auth" in write_fields and the endpoint returns authentication data.
			// Authentication endpoints (e.g., login methods) return auth metadata that users may want
			// as a complete JSON object (client_token, accessor, policies, metadata, etc.).
			if writeField == "auth" && authMap != nil {
				addToWriteData(writeData, writeDataMap, writeField, authMap)
				foundFields[writeField] = true
				continue
			}

			// 5) Check for individual fields within Auth (e.g., "client_token", "accessor", "policies").
			// When User requests a specific Auth field by name and the endpoint returns authentication data.
			// Allows extracting specific auth fields without needing the entire auth object.
			// Common fields: client_token, accessor, policies, metadata, lease_duration, renewable.
			if authMap != nil {
				if v, ok := authMap[writeField]; ok {
					addToWriteData(writeData, writeDataMap, writeField, v)
					foundFields[writeField] = true
					continue
				}

				// Special alias: Allow "token" as a shorthand for "client_token" in Auth responses.
				// Provides backward compatibility and convenience for users expecting "token" instead of "client_token".
				if writeField == "token" {
					if v, ok := authMap["client_token"]; ok {
						addToWriteData(writeData, writeDataMap, writeField, v)
						foundFields[writeField] = true
						continue
					}
				}
			}

			// 6) Check top-level response fields for lease and renewal information.
			// When User requests lease_duration, lease_id, or renewable and the response includes lease data.
			// Some Vault responses (especially dynamic secrets) include lease information at the top level
			// rather than in Data, Auth, or WrapInfo. These fields control secret lifecycle and renewal.
			topLevel := map[string]interface{}{
				"lease_duration": response.LeaseDuration,
				"lease_id":       response.LeaseID,
				"renewable":      response.Renewable,
			}
			if v, ok := topLevel[writeField]; ok {
				addToWriteData(writeData, writeDataMap, writeField, v)
				foundFields[writeField] = true
				continue
			}

			// Field was not found in any location - add a warning
			resp.Diagnostics.AddWarning(
				"Write field not found",
				fmt.Sprintf("The requested write_field %q was not found in the response from %s. "+
					"Available locations checked: response.Data, wrap_info, auth, and top-level fields (lease_duration, lease_id, renewable).",
					writeField, path),
			)
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
		// Check if write_fields was specified
		if !data.WriteFields.IsNull() && !data.WriteFields.IsUnknown() {
			var writeFields []string
			resp.Diagnostics.Append(data.WriteFields.ElementsAs(ctx, &writeFields, false)...)
			if !resp.Diagnostics.HasError() && len(writeFields) > 0 {
				resp.Diagnostics.AddWarning(
					"No Response Data Available",
					fmt.Sprintf("write_fields was specified but the endpoint %q returned no response data to extract. "+
						"The write operation may have succeeded, but no data is available to populate write_data or write_data_json. "+
						"This can occur when the endpoint does not return any data in its response.", path),
				)
			}
		}
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
