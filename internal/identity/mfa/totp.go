// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package mfa

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	MethodTypeTOTP   = "totp"
	ResourceNameTOTP = resourceNamePrefix + MethodTypeTOTP
	algSHA1          = "SHA1"
	algSHA256        = "SHA256"
	algSHA512        = "SHA512"
	algDefault       = algSHA256
)

var (
	algChoices = []string{algSHA1, algSHA256, algSHA512}

	totpSchemaMap = map[string]*schema.Schema{
		consts.FieldIssuer: {
			Type:        schema.TypeString,
			Required:    true,
			Description: `The name of the key's issuing organization.`,
		},
		consts.FieldPeriod: {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     30,
			Description: `The length of time in seconds used to generate a counter for the TOTP token calculation.`,
		},
		consts.FieldKeySize: {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     20,
			Description: `Specifies the size in bytes of the generated key.`,
		},
		consts.FieldQRSize: {
			Type:        schema.TypeInt,
			Computed:    true,
			Optional:    true,
			Description: `The pixel size of the generated square QR code.`,
		},
		consts.FieldAlgorithm: {
			Type:             schema.TypeString,
			Optional:         true,
			Default:          algDefault,
			ValidateDiagFunc: provider.GetValidateDiagChoices(algChoices),
			Description: fmt.Sprintf(`Specifies the hashing algorithm used to generate the TOTP code. `+
				`Options include %s.`, strings.Join(algChoices, ", ")),
		},
		consts.FieldDigits: {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     6,
			Description: `The number of digits in the generated TOTP token. This value can either be 6 or 8`,
		},
		consts.FieldSkew: {
			Type:     schema.TypeInt,
			Optional: true,
			Default:  1,
			Description: `The number of delay periods that are allowed when validating a TOTP token. ` +
				`This value can either be 0 or 1.`,
		},
		consts.FieldMaxValidationAttempts: {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     5,
			Description: `The maximum number of consecutive failed validation attempts allowed.`,
		},
	}
)

// GetTOTPSchemaResource returns the resource needed to provision an identity/mfa/totp resource.
func GetTOTPSchemaResource() (*schema.Resource, error) {
	config, err := NewContextFuncConfig(MethodTypeTOTP, PathTypeMethodID, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	// ensure that the qr_size field can be set to 0
	config.setAPIValueGetter(consts.FieldQRSize, util.GetAPIRequestValueOkExists)

	return getMethodSchemaResource(totpSchemaMap, config), nil
}
