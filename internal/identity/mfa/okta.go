// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package mfa

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	MethodTypeOKTA   = "okta"
	ResourceNameOKTA = resourceNamePrefix + MethodTypeOKTA
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

// GetOKTASchemaResource returns the resource needed to provision an identity/mfa/okta resource.
func GetOKTASchemaResource() (*schema.Resource, error) {
	config, err := NewContextFuncConfig(MethodTypeOKTA, PathTypeMethodID, nil, nil, nil, nil)
	// TODO: the primary_email field is not included in the response
	// from vault-10.x and up. Its value will be derived the from resource data
	// if not present in the response from Vault.
	config.copyQuirks = []string{consts.FieldPrimaryEmail}
	if err != nil {
		return nil, err
	}

	config.setAPIValueGetter(consts.FieldUsernameFormat, util.GetAPIRequestValue)

	return getMethodSchemaResource(oktaSchemaMap, config), nil
}
