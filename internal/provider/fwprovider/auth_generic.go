// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginGenericSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault with an existing auth method using auth/<mount>/login",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldPath: schema.StringAttribute{
					Required: true,
				},
				consts.FieldParameters: schema.MapAttribute{
					Optional:    true,
					ElementType: types.StringType,
					Sensitive:   true,
				},
				consts.FieldMethod: schema.StringAttribute{
					Optional: true,
				},
			},
		},
	}, consts.MountTypeNone)
}
