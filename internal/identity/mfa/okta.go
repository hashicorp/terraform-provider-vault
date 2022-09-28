package mfa

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	MethodTypeOKTA   = "okta"
	ResourceNameOKTA = resourceNamePrefix + "_" + MethodTypeOKTA
)

var oktaSchemaMap = map[string]*schema.Schema{
	consts.FieldUsernameFormat: {
		Type:        schema.TypeString,
		Description: "A template string for mapping Identity names to MFA methods.",
		Optional:    true,
	},
	consts.FieldOrgName: {
		Type:        schema.TypeString,
		Required:    true,
		Description: `Name of the organization to be used in the Okta API.`,
	},
	consts.FieldAPIToken: {
		Type:        schema.TypeString,
		Required:    true,
		Sensitive:   true,
		Description: `Okta API token.`,
	},
	consts.FieldBaseURL: {
		Type:        schema.TypeString,
		Optional:    true,
		Description: `The base domain to use for API requests.`,
	},
	consts.FieldPrimaryEmail: {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: `Only match the primary email for the account.`,
	},
}

func GetOKTASchemaResource() *schema.Resource {
	m := oktaSchemaMap
	config := NewContextFuncConfig(MethodTypeOKTA, m, nil)
	r := &schema.Resource{
		Schema:        m,
		CreateContext: GetCreateContextFunc(config),
		UpdateContext: GetUpdateContextFunc(config),
		ReadContext:   GetReadContextFunc(config),
		DeleteContext: GetDeleteContextFunc(config),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}

	return mustAddCommonSchema(r)
}
