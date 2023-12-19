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

func legacyBaseSchema() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		// Add an 'id' field to the base schema because
		//   1. The id field was implicitly added in the SDKv2, so we must
		//      explicitly add it for existing resources, otherwise its a
		//      breaking change for practitioners.
		//   2. The id field is required for acceptance testing with the SDKv2
		//      package.
		// See:
		//   https://developer.hashicorp.com/terraform/plugin/framework/acctests#no-id-found-in-attributes
		//   https://github.com/hashicorp/terraform-plugin-framework/issues/896
		"id": schema.StringAttribute{
			Computed: true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
	}
}

type schemaFunc func() map[string]schema.Attribute

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

func mustAddSchema(s *schema.Schema, schemaFuncs ...schemaFunc) {
	for _, f := range schemaFuncs {
		for k, v := range f() {
			if _, ok := s.Attributes[k]; ok {
				panic(fmt.Sprintf("cannot add schema field %q, already exists in the Schema map", k))
			}

			s.Attributes[k] = v
		}
	}
}

// MustAddBaseSchema adds the schema fields that are required for all
// resources and data sources.
//
// This should be called from a resources or data source's Schema() method.
func MustAddBaseSchema(s *schema.Schema) {
	mustAddSchema(s, baseSchema)
}

// MustAddLegacyBaseSchema adds the schema fields that are required for
// resources and data sources that have been migrated from SDKv2 to the
// Terraform Plugin Framework.
//
// This should be called from a resources or data source's Schema() method.
func MustAddLegacyBaseSchema(s *schema.Schema) {
	mustAddSchema(s, baseSchema)
	mustAddSchema(s, legacyBaseSchema)
}
