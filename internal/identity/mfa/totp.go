package mfa

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	MethodTypeTOTP   = "totp"
	ResourceNameTOTP = resourceNamePrefix + "_" + MethodTypeTOTP
)

var totpSchemaMap = map[string]*schema.Schema{
	consts.FieldUsernameFormat: {
		Type:        schema.TypeString,
		Optional:    true,
		Description: `A template string for mapping Identity names to MFA methods.`,
	},
	consts.FieldIssuer: {
		Type:        schema.TypeString,
		Required:    true,
		Description: `The name of the key's issuing organization.`,
	},
	consts.FieldPeriod: {
		Type:        schema.TypeInt,
		Optional:    true,
		Computed:    true,
		Description: `The length of time in seconds used to generate a counter for the TOTP token calculation.`,
	},
	consts.FieldKeySize: {
		Type:        schema.TypeInt,
		Optional:    true,
		Computed:    true,
		Description: `Specifies the size in bytes of the generated key.`,
	},
	consts.FieldQRSize: {
		Type:        schema.TypeInt,
		Optional:    true,
		Computed:    true,
		Description: `The pixel size of the generated square QR code.`,
	},
	consts.FieldAlgorithm: {
		Type:     schema.TypeString,
		Optional: true,
		Computed: true,
		Description: `Specifies the hashing algorithm used to generate the TOTP code. ` +
			`Options include "SHA1", "SHA256" and "SHA512".`,
	},
	consts.FieldDigits: {
		Type:        schema.TypeInt,
		Optional:    true,
		Computed:    true,
		Description: `The number of digits in the generated TOTP token. This value can either be 6 or 8`,
	},
	consts.FieldSkew: {
		Type:     schema.TypeInt,
		Optional: true,
		Computed: true,
		Description: `The number of delay periods that are allowed when validating a TOTP token. ` +
			`This value can either be 0 or 1.`,
	},
	consts.FieldMaxValidationAttempts: {
		Type:        schema.TypeInt,
		Optional:    true,
		Computed:    true,
		Description: `The maximum number of consecutive failed validation attempts allowed.`,
	},
}

func GetTOTPSchemaResource() *schema.Resource {
	m := totpSchemaMap
	config := NewContextFuncConfig(MethodTypeTOTP, m, nil)
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
