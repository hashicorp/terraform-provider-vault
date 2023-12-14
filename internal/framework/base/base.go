package base

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
)

// BaseModel describes common fields for all of the Terraform resource data models
//
// Ideally this struct would be imbedded into all Resources and DataSources.
// However, the Terraform Plugin Framework doesn't support unmarshalling nested
// structs. See https://github.com/hashicorp/terraform-plugin-framework/issues/242
// So for now, we must duplicate all fields.
type BaseModel struct {
	ID        types.String `tfsdk:"id"`
	Namespace types.String `tfsdk:"namespace"`
}

func baseSchema() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		// Required for acceptance testing
		// https://developer.hashicorp.com/terraform/plugin/framework/acctests#no-id-found-in-attributes
		"id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "ID required by the testing framework",
		},
		consts.FieldNamespace: schema.StringAttribute{
			Optional: true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},
			MarkdownDescription: "Target namespace. (requires Enterprise)",
			Validators: []validator.String{
				validators.PathValidator(),
			},
		},
	}
}

func MustAddBaseSchema(s *schema.Schema) {
	for k, v := range baseSchema() {
		if _, ok := s.Attributes[k]; ok {
			panic(fmt.Sprintf("cannot add schema field %q, already exists in the Schema map", k))
		}

		s.Attributes[k] = v
	}
}
