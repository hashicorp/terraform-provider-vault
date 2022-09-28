package mfa

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	MethodTypeDuo   = "duo"
	ResourceNameDuo = resourceNamePrefix + "_" + MethodTypeDuo
)

var duoSchemaMap = map[string]*schema.Schema{
	consts.FieldUsernameFormat: {
		Type:        schema.TypeString,
		Description: "A template string for mapping Identity names to MFA methods.",
		Optional:    true,
	},
	consts.FieldSecretKey: {
		Type:        schema.TypeString,
		Required:    true,
		Description: "Secret key for Duo",
		Sensitive:   true,
	},
	consts.FieldIntegrationKey: {
		Type:        schema.TypeString,
		Required:    true,
		Description: "Integration key for Duo",
		Sensitive:   true,
	},
	consts.FieldAPIHostname: {
		Type:        schema.TypeString,
		Required:    true,
		Description: "API hostname for Duo",
	},
	consts.FieldPushInfo: {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Secret key for Duo",
	},
	consts.FieldUsePasscode: {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Require passcode upon MFA validation.",
	},
}

func GetDuoSchemaResource() *schema.Resource {
	m := duoSchemaMap
	config := NewContextFuncConfig(MethodTypeDuo, m, nil)
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
