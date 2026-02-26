// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginUserpassSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the userpass method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldUsername: schema.StringAttribute{
					// can be set via an env var
					Optional:    true,
					Description: "Login with username",
				},
				consts.FieldPassword: schema.StringAttribute{
					Optional:    true,
					Description: "Login with password",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtParent().AtName(consts.FieldPasswordFile),
						),
					},
				},
				consts.FieldPasswordFile: schema.StringAttribute{
					Optional:    true,
					Description: "Login with password from a file",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtParent().AtName(consts.FieldPassword),
						),
					},
				},
			},
		},
	}, consts.MountTypeUserpass)
}
