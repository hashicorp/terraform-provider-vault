package codegen

import "github.com/hashicorp/vault/sdk/framework"

// endpointRegistry is a registry of all the endpoints we'd
// like to have generated, along with the type of template
// we should use.
// IMPORTANT NOTE: To support high quality, only add one
// endpoint per PR.
var endpointRegistry = map[string]*additionalInfo{
	"/transform/alphabet/{name}": {
		Type: tfTypeResource,
	},
	"/transform/decode/{role_name}": {
		Type: tfTypeDataSource,
		AdditionalParameters: []templatableParam{
			{
				OASParameter: &framework.OASParameter{
					Name:        "decoded_value",
					Description: "The result of decoding a value.",
					Schema: &framework.OASSchema{
						Type:         "string",
						DisplayAttrs: &framework.DisplayAttributes{},
					},
				},
				Computed: true,
			},
			{
				OASParameter: &framework.OASParameter{
					Name:        "batch_results",
					Description: "The result of decoding batch_input.",
					Schema: &framework.OASSchema{
						Type: "array",
						Items: &framework.OASSchema{
							Type: "object",
						},
						DisplayAttrs: &framework.DisplayAttributes{},
					},
				},
				Computed: true,
			},
		},
	},
	"/transform/encode/{role_name}": {
		Type: tfTypeDataSource,
		AdditionalParameters: []templatableParam{
			{
				OASParameter: &framework.OASParameter{
					Name:        "encoded_value",
					Description: "The result of encoding a value.",
					Schema: &framework.OASSchema{
						Type:         "string",
						DisplayAttrs: &framework.DisplayAttributes{},
					},
				},
				Computed: true,
			},
			{
				OASParameter: &framework.OASParameter{
					Name:        "batch_results",
					Description: "The result of encoding batch_input.",
					Schema: &framework.OASSchema{
						Type: "array",
						Items: &framework.OASSchema{
							Type: "object",
						},
						DisplayAttrs: &framework.DisplayAttributes{},
					},
				},
				Computed: true,
			},
		},
	},
	"/transform/role/{name}": {
		Type: tfTypeResource,
	},
	"/transform/template/{name}": {
		Type: tfTypeResource,
	},
	"/transform/transformation/{name}": {
		Type: tfTypeResource,
		AdditionalParameters: []templatableParam{
			{
				OASParameter: &framework.OASParameter{
					Name:        "templates",
					Description: "Templates configured for transformation.",
					Schema: &framework.OASSchema{
						Type: "array",
						Items: &framework.OASSchema{
							Type: "string",
						},
						DisplayAttrs: &framework.DisplayAttributes{},
					},
				},
				Computed: true,
			},
		},
	},
}

// tfType is the type of Terraform code to generate.
type tfType int

const (
	tfTypeUnset tfType = iota
	tfTypeDataSource
	tfTypeResource
)

// DocType returns the type of documentation that should be generated:
// - d: data-source
// - r: resource
// This is in accordance with the Terraform Registries *legacy* naming scheme.
// TODO: Migrate to updated registry documentation file structure.
func (t tfType) DocType() string {
	switch t {
	case tfTypeDataSource:
		return "d"
	case tfTypeResource:
		return "r"
	}
	return "unset"
}

func (t tfType) String() string {
	switch t {
	case tfTypeDataSource:
		return "datasource"
	case tfTypeResource:
		return "resource"
	}
	return "unset"
}

type additionalInfo struct {
	Type                 tfType
	AdditionalParameters []templatableParam
}
