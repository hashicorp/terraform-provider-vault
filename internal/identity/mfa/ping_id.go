// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mfa

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	MethodTypePingID   = "pingid"
	ResourceNamePingID = resourceNamePrefix + MethodTypePingID
)

var pingIDSchemaMap = map[string]*schema.Schema{
	consts.FieldUsernameFormat: {
		Type:        schema.TypeString,
		Optional:    true,
		Description: `A template string for mapping Identity names to MFA methods.`,
	},
	consts.FieldSettingsFileBase64: {
		Type:     schema.TypeString,
		Required: true,
		Description: `A base64-encoded third-party settings contents as retrieved from ` +
			`PingID's configuration page.`,
	},
	consts.FieldUseSignature: {
		Type:     schema.TypeBool,
		Computed: true,
		ForceNew: true,
		Description: fmt.Sprintf(`Use signature value, `+
			`derived from %q`, consts.FieldSettingsFileBase64),
	},
	consts.FieldIdpURL: {
		Type:     schema.TypeString,
		Computed: true,
		ForceNew: true,
		Description: fmt.Sprintf(`The IDP URL, `+
			`derived from %q`, consts.FieldSettingsFileBase64),
	},
	consts.FieldAdminURL: {
		Type:     schema.TypeString,
		Computed: true,
		ForceNew: true,
		Description: fmt.Sprintf(`The admin URL, `+
			`derived from %q`, consts.FieldSettingsFileBase64),
	},
	consts.FieldAuthenticatorURL: {
		Type:     schema.TypeString,
		Computed: true,
		ForceNew: true,
		Description: fmt.Sprintf(`A unique identifier of the organization, `+
			`derived from %q`, consts.FieldSettingsFileBase64),
	},
	consts.FieldOrgAlias: {
		Type:     schema.TypeString,
		Computed: true,
		ForceNew: true,
		Description: fmt.Sprintf(`The name of the PingID client organization, `+
			`derived from %q`, consts.FieldSettingsFileBase64),
	},
}

// GetPingIDSchemaResource returns the resource needed to provision an identity/mfa/pingid resource.
func GetPingIDSchemaResource() (*schema.Resource, error) {
	config, err := NewContextFuncConfig(MethodTypePingID, PathTypeMethodID, nil, []string{
		consts.FieldType,
		consts.FieldUseSignature,
		consts.FieldIdpURL,
		consts.FieldAdminURL,
		consts.FieldAuthenticatorURL,
		consts.FieldOrgAlias,
	}, nil, nil)
	if err != nil {
		return nil, err
	}

	return getMethodSchemaResource(pingIDSchemaMap, config), nil
}
