// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package rotate

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/action"
	actionschema "github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
)

const defaultTimeoutSeconds = 1800

var _ action.ActionWithConfigure = (*RotateRootAction)(nil)

type RotateRootAction struct {
	base.ActionWithConfigure
}

type rotateRootModel struct {
	base.BaseModel
	Backend        types.String `tfsdk:"backend"`
	Name           types.String `tfsdk:"name"`
	TimeoutSeconds types.Int64  `tfsdk:"timeout_seconds"`
}

func NewRotateRootAction() action.Action {
	return &RotateRootAction{}
}

func (a *RotateRootAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret_backend_rotate_root"
}

func (a *RotateRootAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = actionschema.Schema{
		MarkdownDescription: "Rotates the root credentials for a secret backend connection. " +
			"The new password is not accessible after rotation.",
		Attributes: map[string]actionschema.Attribute{
			consts.FieldBackend: actionschema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The path of the secret backend mount.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			consts.FieldName: actionschema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the connection to rotate root credentials for.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"timeout_seconds": actionschema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Maximum time in seconds to wait for the rotation to complete. Defaults to 1800.",
				Validators: []validator.Int64{
					int64validator.Between(60, 7200),
				},
			},
		},
	}
	base.MustAddBaseActionSchema(&resp.Schema)
}

func (a *RotateRootAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config rotateRootModel
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

	cli, err := client.GetClient(ctx, a.Meta(), config.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get Vault client",
			fmt.Sprintf("Error configuring Vault client: %s", err),
		)
		return
	}

	rotatePath := fmt.Sprintf("%s/rotate-root/%s", config.Backend.ValueString(), config.Name.ValueString())

	resp.SendProgress(action.InvokeProgressEvent{
		Message: fmt.Sprintf("Rotating root credentials at %s", rotatePath),
	})

	if _, err := cli.Logical().WriteWithContext(ctx, rotatePath, map[string]any{}); err != nil {
		resp.Diagnostics.AddError(
			"Failed to rotate root credentials",
			fmt.Sprintf("Error rotating root credentials at %q: %s", rotatePath, err),
		)
		return
	}

	resp.SendProgress(action.InvokeProgressEvent{
		Message: fmt.Sprintf("Successfully rotated root credentials at %s", rotatePath),
	})
}
