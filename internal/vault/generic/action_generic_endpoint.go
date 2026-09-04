// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package generic

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/action"
	actionschema "github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
)

const defaultTimeoutSeconds = 1800

var _ action.ActionWithConfigure = (*GenericEndpointAction)(nil)

type GenericEndpointAction struct {
	base.ActionWithConfigure
}

type genericEndpointModel struct {
	base.BaseModel
	Path           types.String `tfsdk:"path"`
	DataJSON       types.String `tfsdk:"data_json"`
	TimeoutSeconds types.Int64  `tfsdk:"timeout_seconds"`
}

func NewGenericEndpointAction() action.Action {
	return &GenericEndpointAction{}
}

func (a *GenericEndpointAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_generic_endpoint"
}

func (a *GenericEndpointAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = actionschema.Schema{
		MarkdownDescription: "Writes to an arbitrary Vault endpoint. Commonly used to trigger " +
			"operational endpoints such as `rotate-root`, which have no Terraform-managed state.",
		Attributes: map[string]actionschema.Attribute{
			consts.FieldPath: actionschema.StringAttribute{
				Required: true,
				MarkdownDescription: "Full path of the Vault endpoint to write to, without a " +
					"leading slash. For example, `aws/config/rotate-root` or " +
					"`database/rotate-root/my-connection`.",
				Validators: []validator.String{
					validators.PathValidator(),
				},
			},
			consts.FieldDataJSON: actionschema.StringAttribute{
				Optional: true,
				MarkdownDescription: "JSON-encoded request body to write. Omit for endpoints that " +
					"take no parameters, such as `rotate-root`.",
				Validators: []validator.String{
					validators.JSONObjectValidator(),
				},
			},
			"timeout_seconds": actionschema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Maximum time in seconds to wait for the write to complete. Defaults to 1800.",
				Validators: []validator.Int64{
					int64validator.Between(60, 7200),
				},
			},
		},
	}
	base.MustAddBaseActionSchema(&resp.Schema)
}

func (a *GenericEndpointAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config genericEndpointModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeoutSecs := int64(defaultTimeoutSeconds)
	if !config.TimeoutSeconds.IsNull() {
		timeoutSecs = config.TimeoutSeconds.ValueInt64()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	data := map[string]any{}
	if !config.DataJSON.IsNull() {
		if err := json.Unmarshal([]byte(config.DataJSON.ValueString()), &data); err != nil {
			resp.Diagnostics.AddError(
				"Invalid data_json",
				fmt.Sprintf("Error parsing data_json as a JSON object: %s", err),
			)
			return
		}
	}

	cli, err := client.GetClient(ctx, a.Meta(), config.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get Vault client",
			fmt.Sprintf("Error configuring Vault client: %s", err),
		)
		return
	}

	path := config.Path.ValueString()

	resp.SendProgress(action.InvokeProgressEvent{
		Message: fmt.Sprintf("Writing to %s", path),
	})

	if _, err := cli.Logical().WriteWithContext(ctx, path, data); err != nil {
		resp.Diagnostics.AddError(
			"Failed to write to Vault endpoint",
			fmt.Sprintf("Error writing to %q: %s", path, err),
		)
		return
	}

	resp.SendProgress(action.InvokeProgressEvent{
		Message: fmt.Sprintf("Successfully wrote to %s", path),
	})
}
