// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginJWTSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the jwt method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldRole: schema.StringAttribute{
					Required:    true,
					Description: "Name of the login role.",
				},
				consts.FieldJWT: schema.StringAttribute{
					// can be set via an env var
					Optional:    true,
					Description: "A signed JSON Web Token.",
				},
			},
		},
	}, consts.MountTypeJWT)
}
