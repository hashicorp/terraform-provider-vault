// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"

	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

const activationFlagsPath = "sys/activation-flags"

var (
	_ resource.Resource                = &ActivationFlagsResource{}
	_ resource.ResourceWithConfigure   = &ActivationFlagsResource{}
	_ resource.ResourceWithImportState = &ActivationFlagsResource{}
)

const (
	activationFlagFeatureField         = "feature"
	activationFlagActivatePathTemplate = activationFlagsPath + "/%s/activate"
	activationFlagsAPIActivatedField   = "activated"
	activationFlagsAPIUnactivatedField = "unactivated"
)

// NewActivationFlagsResource returns the implementation for this resource
func NewActivationFlagsResource() resource.Resource {
	return &ActivationFlagsResource{}
}

// ActivationFlagsResource implements the resource
type ActivationFlagsResource struct {
	base.ResourceWithConfigure
}

// ActivationFlagsModel describes the Terraform resource data model
type ActivationFlagsModel struct {
	base.BaseModel

	ID      types.String `tfsdk:"id"`
	Feature types.String `tfsdk:"feature"`
}

type activationFlagsState struct {
	Activated   []string
	Unactivated []string
}

// Metadata defines the resource name
func (r *ActivationFlagsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_activation_flags"
}

// Schema defines the resource schema
func (r *ActivationFlagsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldID: schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldNamespace: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Root-namespace-only endpoint; this attribute is always null.",
			},
			activationFlagFeatureField: schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				MarkdownDescription: "Exact feature key to activate with PUT /sys/activation-flags/:feature/activate.",
			},
		},
		MarkdownDescription: "Activates a single activation flag in Vault.",
	}
}

func (r *ActivationFlagsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldID), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), types.StringNull())...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(activationFlagFeatureField), req.ID)...)
}

// Create is called during terraform apply
func (r *ActivationFlagsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ActivationFlagsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), "")
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	feature, ok := getDesiredActivationFlag(data, &resp.Diagnostics)
	if !ok {
		return
	}

	if err := activateFlag(ctx, cli, feature); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	if !readActivationFlagState(ctx, cli, &data, &resp.Diagnostics) {
		return
	}

	data.Namespace = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during terraform plan, apply, and refresh
func (r *ActivationFlagsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ActivationFlagsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), "")
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	feature, ok := getDesiredActivationFlag(data, &resp.Diagnostics)
	if !ok {
		return
	}

	flagsState, err := readActivationFlags(ctx, cli)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	if activationFlagIsListed(feature, flagsState.Activated) {
		data.ID = types.StringValue(feature)
		data.Namespace = types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	if !activationFlagIsListed(feature, flagsState.Unactivated) {
		resp.Diagnostics.AddWarning(
			"Activation flag no longer reported by Vault",
			fmt.Sprintf("Activation flag %q was not returned by GET /%s. Removing it from Terraform state.", feature, activationFlagsPath),
		)
	}

	resp.State.RemoveResource(ctx)
}

// Update is called during terraform apply
func (r *ActivationFlagsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ActivationFlagsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), "")
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	feature, ok := getDesiredActivationFlag(data, &resp.Diagnostics)
	if !ok {
		return
	}

	if err := activateFlag(ctx, cli, feature); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	if !readActivationFlagState(ctx, cli, &data, &resp.Diagnostics) {
		return
	}

	data.Namespace = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during terraform destroy
func (r *ActivationFlagsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning(
		"Activation flag remains enabled in Vault",
		"The public Vault API exposes activation but not deactivation for activation flags. Terraform will remove this resource from state, but it cannot disable a flag that was previously activated.",
	)

	resp.State.RemoveResource(ctx)
}

func getDesiredActivationFlag(data ActivationFlagsModel, diagnostics *diag.Diagnostics) (string, bool) {
	if data.Feature.IsNull() || data.Feature.IsUnknown() {
		diagnostics.AddError("Missing activation flag feature", "The feature attribute must be known before Terraform can activate it.")
		return "", false
	}

	feature := data.Feature.ValueString()
	if feature == "" {
		diagnostics.AddError("Missing activation flag feature", "The feature attribute must not be empty.")
		return "", false
	}

	return feature, true
}

func readActivationFlagState(ctx context.Context, cli *api.Client, data *ActivationFlagsModel, diagnostics *diag.Diagnostics) bool {
	feature, ok := getDesiredActivationFlag(*data, diagnostics)
	if !ok {
		return false
	}

	flagsState, err := readActivationFlags(ctx, cli)
	if err != nil {
		diagnostics.AddError(errutil.VaultReadErr(err))
		return false
	}

	if !activationFlagIsListed(feature, flagsState.Activated) {
		diagnostics.AddError(
			"Error Reading Activation Flag",
			fmt.Sprintf("Activation flag %q is not active in Vault after PUT /%s.", feature, fmt.Sprintf(activationFlagActivatePathTemplate, url.PathEscape(feature))),
		)
		return false
	}

	data.ID = types.StringValue(feature)
	data.Namespace = types.StringNull()

	return true
}

func activateFlag(ctx context.Context, cli *api.Client, feature string) error {
	flagsState, err := readActivationFlags(ctx, cli)
	if err != nil {
		return err
	}

	if err := validateActivationFlag(feature, flagsState); err != nil {
		return err
	}

	if activationFlagIsListed(feature, flagsState.Activated) {
		return nil
	}

	activatePath := fmt.Sprintf(activationFlagActivatePathTemplate, url.PathEscape(feature))
	if _, err := cli.Logical().WriteWithContext(ctx, activatePath, map[string]interface{}{}); err != nil {
		return fmt.Errorf("error activating flag %q: %w", feature, err)
	}

	return nil
}

func readActivationFlags(ctx context.Context, cli *api.Client) (*activationFlagsState, error) {
	vaultResp, err := cli.Logical().ReadWithContext(ctx, activationFlagsPath)
	if err != nil {
		return nil, err
	}

	if vaultResp == nil {
		title, detail := errutil.VaultReadResponseNil()
		return nil, fmt.Errorf("%s: %s", title, detail)
	}

	activated, err := getActivationFlagsFromResponse(vaultResp.Data, activationFlagsAPIActivatedField)
	if err != nil {
		return nil, err
	}

	unactivated, err := getActivationFlagsFromResponse(vaultResp.Data, activationFlagsAPIUnactivatedField)
	if err != nil {
		return nil, err
	}

	return &activationFlagsState{
		Activated:   activated,
		Unactivated: unactivated,
	}, nil
}

func validateActivationFlag(feature string, flagsState *activationFlagsState) error {
	availableFlags := make(map[string]struct{}, len(flagsState.Activated)+len(flagsState.Unactivated))
	for _, flag := range flagsState.Activated {
		availableFlags[flag] = struct{}{}
	}
	for _, flag := range flagsState.Unactivated {
		availableFlags[flag] = struct{}{}
	}

	if _, ok := availableFlags[feature]; ok {
		return nil
	}

	suggestion := suggestActivationFlagName(feature, availableFlags)
	if suggestion != "" {
		return fmt.Errorf(
			"activation flag %q was not returned by GET /%s. Use the exact feature key reported by Vault. Did you mean %q?",
			feature,
			activationFlagsPath,
			suggestion,
		)
	}

	return fmt.Errorf(
		"activation flag %q was not returned by GET /%s. Use the exact feature key reported by Vault",
		feature,
		activationFlagsPath,
	)
}

func suggestActivationFlagName(flag string, availableFlags map[string]struct{}) string {
	if !strings.Contains(flag, "_") {
		return ""
	}

	candidate := strings.ReplaceAll(flag, "_", "-")
	if _, ok := availableFlags[candidate]; ok {
		return candidate
	}

	return ""
}

func getActivationFlagsFromResponse(data map[string]interface{}, field string) ([]string, error) {
	if data == nil {
		return []string{}, nil
	}

	raw, ok := data[field]
	if !ok {
		return []string{}, nil
	}

	return rawActivationFlagsToStrings(raw, field)
}

func rawActivationFlagsToStrings(raw interface{}, field string) ([]string, error) {
	switch value := raw.(type) {
	case nil:
		return []string{}, nil
	case []string:
		return append([]string(nil), value...), nil
	case []interface{}:
		flags := make([]string, 0, len(value))
		for _, item := range value {
			flag, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("activation flags field %q contained non-string value of type %T", field, item)
			}
			flags = append(flags, flag)
		}
		return flags, nil
	default:
		return nil, fmt.Errorf("activation flags field %q had unexpected type %T", field, raw)
	}
}

func activationFlagIsListed(feature string, flags []string) bool {
	for _, flag := range flags {
		if flag == feature {
			return true
		}
	}

	return false
}
