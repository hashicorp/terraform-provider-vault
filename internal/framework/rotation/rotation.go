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
	RotationPeriod           any    `json:"rotation_period,omitempty" mapstructure:"rotation_period"`
	RotationSchedule         string `json:"rotation_schedule,omitempty" mapstructure:"rotation_schedule"`
	RotationWindow           any    `json:"rotation_window,omitempty" mapstructure:"rotation_window"`
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

	switch v := apiModel.RotationPeriod.(type) {
	case nil:
		model.RotationPeriod = types.Int64Null()
	case float64:
		if v != 0 {
			model.RotationPeriod = types.Int64Value(int64(v))
		} else {
			model.RotationPeriod = types.Int64Null()
		}
	case int:
		if v != 0 {
			model.RotationPeriod = types.Int64Value(int64(v))
		} else {
			model.RotationPeriod = types.Int64Null()
		}
	case int64:
		if v != 0 {
			model.RotationPeriod = types.Int64Value(v)
		} else {
			model.RotationPeriod = types.Int64Null()
		}
	default:
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("unexpected rotation_period value", fmt.Sprintf("unsupported type %T for rotation_period", v)),
		}
	}

	if apiModel.RotationSchedule != "" {
		model.RotationSchedule = types.StringValue(apiModel.RotationSchedule)
	} else {
		model.RotationSchedule = types.StringNull()
	}

	switch v := apiModel.RotationWindow.(type) {
	case nil:
		model.RotationWindow = types.Int64Null()
	case float64:
		if v != 0 {
			model.RotationWindow = types.Int64Value(int64(v))
		} else {
			model.RotationWindow = types.Int64Null()
		}
	case int:
		if v != 0 {
			model.RotationWindow = types.Int64Value(int64(v))
		} else {
			model.RotationWindow = types.Int64Null()
		}
	case int64:
		if v != 0 {
			model.RotationWindow = types.Int64Value(v)
		} else {
			model.RotationWindow = types.Int64Null()
		}
	default:
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("unexpected rotation_window value", fmt.Sprintf("unsupported type %T for rotation_window", v)),
		}
	}

	if apiModel.DisableAutomatedRotation || !model.DisableAutomatedRotation.IsNull() {
		model.DisableAutomatedRotation = types.BoolValue(apiModel.DisableAutomatedRotation)
	}

	return diag.Diagnostics{}
}

// PopulateAutomatedRotationRequestData copies the shared automated rotation
// values into a request payload using explicit empty values to clear removed
// configuration.
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

	apiModel := &AutomatedRotationAPIModel{}
	if diags := PopulateAutomatedRotationAPIFromModel(model, apiModel); diags.HasError() {
		return diags
	}

	requestData[consts.FieldRotationPeriod] = apiModel.RotationPeriod
	requestData[consts.FieldRotationSchedule] = apiModel.RotationSchedule
	requestData[consts.FieldRotationWindow] = apiModel.RotationWindow
	requestData[consts.FieldDisableAutomatedRotation] = apiModel.DisableAutomatedRotation

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
