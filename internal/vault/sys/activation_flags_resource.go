// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"

	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
	activationFlagsID                  = "activation-flags"
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
	base.WithImportByID
}

// ActivationFlagsModel describes the Terraform resource data model
type ActivationFlagsModel struct {
	base.BaseModelLegacy

	ActivatedFlags types.List `tfsdk:"activated_flags"`
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
			consts.FieldActivatedFlags: schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Full set of feature flags that should be activated. Because Vault exposes activation but not public deactivation for activation flags, any flags already activated in Vault must also be declared here.",
			},
		},
		MarkdownDescription: "Manages activation flags in Vault. This is a singleton resource - only one instance should exist per Vault cluster.",
	}

	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// Create is called during terraform apply
func (r *ActivationFlagsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ActivationFlagsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	desiredFlags, ok := getDesiredActivatedFlags(ctx, data, &resp.Diagnostics)
	if !ok {
		return
	}

	if err := reconcileActivatedFlags(ctx, cli, desiredFlags); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	if !readActivationFlagsState(ctx, cli, &data, &resp.Diagnostics) {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during terraform plan, apply, and refresh
func (r *ActivationFlagsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ActivationFlagsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if !readActivationFlagsState(ctx, cli, &data, &resp.Diagnostics) {
		if resp.Diagnostics.HasError() {
			return
		}

		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during terraform apply
func (r *ActivationFlagsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ActivationFlagsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	desiredFlags, ok := getDesiredActivatedFlags(ctx, data, &resp.Diagnostics)
	if !ok {
		return
	}

	if err := reconcileActivatedFlags(ctx, cli, desiredFlags); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	if !readActivationFlagsState(ctx, cli, &data, &resp.Diagnostics) {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during terraform destroy
func (r *ActivationFlagsResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning(
		"Activation flags remain enabled in Vault",
		"The public Vault API exposes activation but not deactivation for activation flags. Terraform will remove this resource from state, but it cannot disable flags that were previously activated.",
	)
}

func getDesiredActivatedFlags(ctx context.Context, data ActivationFlagsModel, diagnostics *diag.Diagnostics) ([]string, bool) {
	if data.ActivatedFlags.IsNull() || data.ActivatedFlags.IsUnknown() {
		return []string{}, true
	}

	var flags []string
	diagnostics.Append(data.ActivatedFlags.ElementsAs(ctx, &flags, false)...)
	if diagnostics.HasError() {
		return nil, false
	}

	return flags, true
}

func readActivationFlagsState(ctx context.Context, cli *api.Client, data *ActivationFlagsModel, diagnostics *diag.Diagnostics) bool {
	vaultResp, err := cli.Logical().ReadWithContext(ctx, activationFlagsPath)
	if err != nil {
		diagnostics.AddError(errutil.VaultReadErr(err))
		return false
	}

	if vaultResp == nil {
		return false
	}

	flags, err := getActivationFlagsFromResponse(vaultResp.Data, activationFlagsAPIActivatedField)
	if err != nil {
		diagnostics.AddError(
			"Error Reading Activation Flags",
			err.Error(),
		)
		return false
	}

	flagsList, diags := types.ListValueFrom(ctx, types.StringType, flags)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return false
	}

	data.ActivatedFlags = flagsList
	data.ID = types.StringValue(activationFlagsID)

	return true
}

func reconcileActivatedFlags(ctx context.Context, cli *api.Client, desiredFlags []string) error {
	flagsState, err := readActivationFlags(ctx, cli)
	if err != nil {
		return err
	}

	if err := validateDesiredActivationFlags(desiredFlags, flagsState); err != nil {
		return err
	}

	currentFlags := flagsState.Activated

	undeclaredFlags := diffActivationFlags(currentFlags, desiredFlags)
	if len(undeclaredFlags) > 0 {
		return fmt.Errorf(
			"Vault already has activated flags not declared in configuration: %s. The public activation flags API does not support deactivation, so activated_flags must include all currently activated flags",
			strings.Join(undeclaredFlags, ", "),
		)
	}

	for _, flag := range diffActivationFlags(desiredFlags, currentFlags) {
		activatePath := fmt.Sprintf(activationFlagActivatePathTemplate, url.PathEscape(flag))
		if _, err := cli.Logical().WriteWithContext(ctx, activatePath, map[string]interface{}{}); err != nil {
			return fmt.Errorf("error activating flag %q: %w", flag, err)
		}
	}

	return nil
}

func readCurrentActivatedFlags(ctx context.Context, cli *api.Client) ([]string, error) {
	flagsState, err := readActivationFlags(ctx, cli)
	if err != nil {
		return nil, err
	}

	return flagsState.Activated, nil
}

func readActivationFlags(ctx context.Context, cli *api.Client) (*activationFlagsState, error) {
	vaultResp, err := cli.Logical().ReadWithContext(ctx, activationFlagsPath)
	if err != nil {
		return nil, err
	}

	if vaultResp == nil {
		return &activationFlagsState{}, nil
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

func validateDesiredActivationFlags(desiredFlags []string, flagsState *activationFlagsState) error {
	availableFlags := make(map[string]struct{}, len(flagsState.Activated)+len(flagsState.Unactivated))
	for _, flag := range flagsState.Activated {
		availableFlags[flag] = struct{}{}
	}
	for _, flag := range flagsState.Unactivated {
		availableFlags[flag] = struct{}{}
	}

	for _, flag := range desiredFlags {
		if _, ok := availableFlags[flag]; ok {
			continue
		}

		suggestion := suggestActivationFlagName(flag, availableFlags)
		if suggestion != "" {
			return fmt.Errorf(
				"activation flag %q was not returned by GET /%s. Use the exact feature key reported by Vault. Did you mean %q?",
				flag,
				activationFlagsPath,
				suggestion,
			)
		}

		return fmt.Errorf(
			"activation flag %q was not returned by GET /%s. Use the exact feature key reported by Vault",
			flag,
			activationFlagsPath,
		)
	}

	return nil
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

func diffActivationFlags(left, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, flag := range right {
		rightSet[flag] = struct{}{}
	}

	result := make([]string, 0)
	seen := make(map[string]struct{}, len(left))
	for _, flag := range left {
		if _, ok := seen[flag]; ok {
			continue
		}
		seen[flag] = struct{}{}
		if _, ok := rightSet[flag]; !ok {
			result = append(result, flag)
		}
	}

	return result
}
