// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package rotation

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// AutomatedRotationModel provides a common framework model for resources that
// expose Vault automated rotation fields using integer-second inputs.
type AutomatedRotationModel struct {
	RotationPeriod           types.Int64  `tfsdk:"rotation_period"`
	RotationSchedule         types.String `tfsdk:"rotation_schedule"`
	RotationWindow           types.Int64  `tfsdk:"rotation_window"`
	DisableAutomatedRotation types.Bool   `tfsdk:"disable_automated_rotation"`
}

// AutomatedRotationAPIModel provides the common API representation for Vault
// automated rotation fields.
type AutomatedRotationAPIModel struct {
	RotationPeriod           int64  `json:"rotation_period,omitempty" mapstructure:"rotation_period"`
	RotationSchedule         string `json:"rotation_schedule,omitempty" mapstructure:"rotation_schedule"`
	RotationWindow           int64  `json:"rotation_window,omitempty" mapstructure:"rotation_window"`
	DisableAutomatedRotation bool   `json:"disable_automated_rotation,omitempty" mapstructure:"disable_automated_rotation"`
}

// MustAddAutomatedRotationSchemas adds the shared automated rotation fields to
// a framework resource or data source schema.
func MustAddAutomatedRotationSchemas(s *schema.Schema) {
	for k, v := range automatedRotationSchema() {
		if _, ok := s.Attributes[k]; ok {
			panic(fmt.Sprintf("cannot add schema field %q, already exists in the Schema map", k))
		}

		s.Attributes[k] = v
	}
}

// PopulateAutomatedRotationAPIFromModel copies the shared automated rotation
// values from a framework model into the API model.
func PopulateAutomatedRotationAPIFromModel(model *AutomatedRotationModel, apiModel *AutomatedRotationAPIModel) diag.Diagnostics {
	if apiModel == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate nil api model", ""),
		}
	}
	if model == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate api model from nil automated rotation model", ""),
		}
	}

	if !model.RotationPeriod.IsNull() && !model.RotationPeriod.IsUnknown() {
		apiModel.RotationPeriod = model.RotationPeriod.ValueInt64()
	} else {
		apiModel.RotationPeriod = int64(0)
	}

	if !model.RotationSchedule.IsNull() && !model.RotationSchedule.IsUnknown() {
		apiModel.RotationSchedule = model.RotationSchedule.ValueString()
	} else {
		apiModel.RotationSchedule = ""
	}

	if !model.RotationWindow.IsNull() && !model.RotationWindow.IsUnknown() {
		apiModel.RotationWindow = model.RotationWindow.ValueInt64()
	} else {
		apiModel.RotationWindow = int64(0)
	}

	if !model.DisableAutomatedRotation.IsNull() && !model.DisableAutomatedRotation.IsUnknown() {
		apiModel.DisableAutomatedRotation = model.DisableAutomatedRotation.ValueBool()
	} else {
		apiModel.DisableAutomatedRotation = false
	}

	return diag.Diagnostics{}
}

// PopulateAutomatedRotationModelFromAPI copies the shared automated rotation
// values from the API model into a framework model.
func PopulateAutomatedRotationModelFromAPI(model *AutomatedRotationModel, apiModel *AutomatedRotationAPIModel) diag.Diagnostics {
	if apiModel == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate automated rotation model from nil api model", ""),
		}
	}
	if model == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate nil automated rotation model", ""),
		}
	}

	model.RotationPeriod = types.Int64Null()
	if apiModel.RotationPeriod != 0 {
		model.RotationPeriod = types.Int64Value(apiModel.RotationPeriod)
	}

	model.RotationSchedule = types.StringNull()
	if apiModel.RotationSchedule != "" {
		model.RotationSchedule = types.StringValue(apiModel.RotationSchedule)
	}

	model.RotationWindow = types.Int64Null()
	if apiModel.RotationWindow != 0 {
		model.RotationWindow = types.Int64Value(apiModel.RotationWindow)
	}

	model.DisableAutomatedRotation = types.BoolNull()
	if apiModel.DisableAutomatedRotation {
		model.DisableAutomatedRotation = types.BoolValue(true)
	}

	return diag.Diagnostics{}
}

// PopulateAutomatedRotationRequestData copies the shared automated rotation
// values into a request payload. Only sends non-zero values to match SDK v2
// behavior and avoid conflicts with Vault's rotation field validation.
// To clear a field, it must be explicitly set to its zero value in the config.
func PopulateAutomatedRotationRequestData(model *AutomatedRotationModel, requestData map[string]interface{}) diag.Diagnostics {
	if requestData == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate nil request data", ""),
		}
	}
	if model == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate request data from nil automated rotation model", ""),
		}
	}

	// Only send rotation fields that have non-zero values to avoid conflicts
	// with Vault's rotation field validation (e.g., rotation_period and
	// rotation_schedule are mutually exclusive).
	//
	// Note: To clear a field that was previously set, the user must explicitly
	// set it to 0/""/false in their config. Removing it from config will leave
	// the existing value in Vault unchanged.
	if !model.RotationPeriod.IsNull() && !model.RotationPeriod.IsUnknown() {
		period := model.RotationPeriod.ValueInt64()
		// Always send if explicitly set, even if zero (to clear the field)
		requestData[consts.FieldRotationPeriod] = period
	}

	if !model.RotationSchedule.IsNull() && !model.RotationSchedule.IsUnknown() {
		schedule := model.RotationSchedule.ValueString()
		// Always send if explicitly set, even if empty (to clear the field)
		requestData[consts.FieldRotationSchedule] = schedule
	}

	if !model.RotationWindow.IsNull() && !model.RotationWindow.IsUnknown() {
		window := model.RotationWindow.ValueInt64()
		// Always send if explicitly set, even if zero (to clear the field)
		requestData[consts.FieldRotationWindow] = window
	}

	if !model.DisableAutomatedRotation.IsNull() && !model.DisableAutomatedRotation.IsUnknown() {
		disable := model.DisableAutomatedRotation.ValueBool()
		// Always send if explicitly set, even if false (to clear the field)
		requestData[consts.FieldDisableAutomatedRotation] = disable
	}

	return diag.Diagnostics{}
}

func automatedRotationSchema() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		consts.FieldRotationPeriod: schema.Int64Attribute{
			Optional:            true,
			MarkdownDescription: "How often to rotate passwords, in seconds. Mutually exclusive with rotation_schedule.",
		},
		consts.FieldRotationSchedule: schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Cron schedule for password rotation. Mutually exclusive with rotation_period.",
		},
		consts.FieldRotationWindow: schema.Int64Attribute{
			Optional:            true,
			MarkdownDescription: "Window of time for password rotation, in seconds.",
		},
		consts.FieldDisableAutomatedRotation: schema.BoolAttribute{
			Optional:            true,
			MarkdownDescription: "Disable automated password rotation.",
		},
	}
}
