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
type BaseModel struct {
	Namespace types.String `tfsdk:"namespace"`
}

func baseSchema() map[string]schema.Attribute {
	return map[string]schema.Attribute{
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
