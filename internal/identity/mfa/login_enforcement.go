// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package mfa

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	MethodTypeLoginEnforcement   = "login-enforcement"
	ResourceNameLoginEnforcement = resourceNamePrefix + "login_enforcement"
)

var loginEnforcementSchemaMap = map[string]*schema.Schema{
	consts.FieldName: {
		Type:        schema.TypeString,
		Required:    true,
		Description: "Login enforcement name.",
	},
	consts.FieldMFAMethodIDs: {
		Type: schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Required:    true,
		Description: `Set of MFA method UUIDs.`,
	},
	consts.FieldAuthMethodAccessors: {
		Type: schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Optional:    true,
		Description: `Set of auth method accessor IDs.`,
	},
	consts.FieldAuthMethodTypes: {
		Type: schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Optional:    true,
		Description: `Set of auth method types.`,
	},
	consts.FieldIdentityGroupIDs: {
		Type: schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Optional:    true,
		Description: `Set of identity group IDs.`,
	},
	consts.FieldIdentityEntityIDs: {
		Type: schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Optional:    true,
		Description: `Set of identity entity IDs.`,
	},
}

// GetLoginEnforcementSchemaResource returns the resource needed to provision an identity/mfa/login-enforcement
// resource.
func GetLoginEnforcementSchemaResource() (*schema.Resource, error) {
	config, err := NewContextFuncConfig(MethodTypeLoginEnforcement, PathTypeName, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	r := getSchemaResource(loginEnforcementSchemaMap, config, mustAddCommonSchema)
	for k, v := range r.Schema {
		switch k {
		case consts.FieldUUID, consts.FieldName:
			v.ForceNew = true
		}
	}

	return r, nil
}
