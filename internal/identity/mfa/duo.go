// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mfa

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	MethodTypeDuo   = "duo"
	ResourceNameDuo = resourceNamePrefix + MethodTypeDuo
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
		Description: "Push information for Duo.",
	},
	consts.FieldUsePasscode: {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Require passcode upon MFA validation.",
	},
}

func GetDuoSchemaResource() (*schema.Resource, error) {
	config, _ := NewContextFuncConfig(MethodTypeDuo, PathTypeMethodID, nil, nil, map[string]string{
		// API is inconsistent between create/update and read.
		"pushinfo": consts.FieldPushInfo,
	})

	return getMethodSchemaResource(duoSchemaMap, config), nil
}
