// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package base

import (
	"fmt"

	ephemeralschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
)

// BaseModel describes common fields for all Terraform resource data models
//
// This struct should be embedded into all Terraform Plugin Framework Resources and Data Sources.
type BaseModel struct {
	Namespace types.String `tfsdk:"namespace"`
}

// BaseModelLegacy describes common fields for all Terraform resource
// data models that have been migrated from SDKv2 to the TF Plugin Framework.
//
// This struct should be embedded into all SDKv2 Resources and Data Sources.
type BaseModelLegacy struct {
	BaseModel

	ID types.String `tfsdk:"id"`
}

// BaseModelEphemeral describes common fields for all Ephemeral resources.
//
// This struct should be embedded into all Ephemeral Resources.
type BaseModelEphemeral struct {
	BaseModel

	// In certain cases, ephemeral resources need to defer provisioning
	// till after certain resources have been created in the Apply step.
	// However, if each input parameter is already known to the Ephemeral
	// resource at Plan time, TF will attempt to open and read the ephemeral
	// resource regardless. For example, if an ephemeral resource depends on a mount
	// and a name parameter, both of which are known at Plan, then TF will try to read
	// the Ephemeral secret even if the mount and name have not yet been created.
	//
	// In order to defer provisioning of the ephemeral resource, we have it depend on a
	// computed attribute MountID for a mount resource, thereby forcing it to defer provisioning.
	// In the TFVP, we know that each Ephemeral resource will definitely have a mount parameter.
	// Adding in MountID enables Ephemeral resource to defer their provisioning if this attribute is set.
	// This attribute does not do anything, and only exists to maintain a proper dependency graph.
	MountID types.String `tfsdk:"mount_id"`
}

// MustAddBaseSchema adds the schema fields that are required for all net new
// resources and data sources built with the TF Plugin Framework.
//
// This should be called from a resources or data source's Schema() method.
func MustAddBaseSchema(s *schema.Schema) {
	mustAddSchema(s, baseSchema)
}

// MustAddBaseEphemeralSchema adds the schema fields that are required for all net new
// resources and data sources built with the TF Plugin Framework.
//
// This should be called from a resources or data source's Schema() method.
func MustAddBaseEphemeralSchema(s *ephemeralschema.Schema) {
	mustAddEphemeralSchema(s, baseEphemeralSchema)
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
		consts.FieldID: schema.StringAttribute{
			Computed: true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
	}
}

type schemaFunc func() map[string]schema.Attribute

type ephemeralSchemaFunc func() map[string]ephemeralschema.Attribute

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

func baseEphemeralSchema() map[string]ephemeralschema.Attribute {
	return map[string]ephemeralschema.Attribute{
		consts.FieldNamespace: ephemeralschema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Target namespace. (requires Enterprise)",
			Validators: []validator.String{
				validators.PathValidator(),
			},
		},
		consts.FieldMountID: ephemeralschema.StringAttribute{
			Optional: true,
			MarkdownDescription: "Terraform ID of the mount resource. Used to defer the provisioning " +
				"of the ephemeral resource till the apply stage.",
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

func mustAddEphemeralSchema(s *ephemeralschema.Schema, schemaFuncs ...ephemeralSchemaFunc) {
	for _, f := range schemaFuncs {
		for k, v := range f() {
			if _, ok := s.Attributes[k]; ok {
				panic(fmt.Sprintf("cannot add schema field %q, already exists in the Schema map", k))
			}

			s.Attributes[k] = v
		}
	}
}
